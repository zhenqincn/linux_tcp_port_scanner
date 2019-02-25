
#include <stdlib.h>
#include <stdio.h>
#include <errno.h>
#include <string.h>
#include <unistd.h>
#include <netdb.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <netinet/in.h>
#include <netinet/ip.h>
#include <errno.h>
#include <arpa/inet.h>
#include <linux/tcp.h>
#include <pthread.h>
#include <fcntl.h>

/*
 * Author：Exploit
 * 这是一个SYN极速扫描的demo
 * 存在的问题：发包的速度要控制，不然丢包很严重
 * 但是在60个端口的范围内有效
 *
 * */

//定义TCP伪报头
typedef struct psd_hdr
{
	unsigned long saddr; //源地址
	unsigned long daddr; //目的地址
	char mbz;
	char ptcl;			 //协议类型
	unsigned short tcpl; //TCP长度

} PSD_HEADER;

//定义TCP报头
typedef struct _tcphdr
{
	unsigned short th_sport; //16位源端口
	unsigned short th_dport; //16位目的端口
	unsigned int th_seq;	 //32位序列号
	unsigned int th_ack;	 //32位确认号
	unsigned char th_lenres; //4位首部长度/4位保留字
	unsigned char th_flag;   //6位标志位
	unsigned short th_win;   //16位窗口大小
	unsigned short th_sum;   //16位校验和
	unsigned short th_urp;   //16位紧急数据偏移量

} TCP_HEADER;

//定义IP报头
typedef struct _iphdr
{
	unsigned char h_lenver; //长度加版本号
	unsigned char tos;
	unsigned short total_len;
	unsigned short ident;
	unsigned short frag_and_flags;
	unsigned char ttl;
	unsigned char proto;
	unsigned short checksum;
	unsigned int sourceIP;
	unsigned int destIP;

} IP_HEADER;

/**
 * 计算校验和
 */
unsigned short checksum(unsigned short *addr, int len)
{
	int nleft = len;
	int sum = 0;
	unsigned short *w = addr;
	unsigned short answer = 0;

	while (nleft > 1)
	{
		sum += *w++;
		nleft -= 2;
	}

	if (nleft == 1)
	{
		*(unsigned char *)(&answer) = *(unsigned char *)w;
		sum += answer;
	}

	sum = (sum >> 16) + (sum & 0xffff);
	sum += (sum >> 16);
	answer = ~sum;
	return (answer);
}

/* 扫描目标*/
struct sockaddr_in target;
struct sockaddr_in myaddr;
int sockfd;
pthread_t pth;

void TCP_Send(int port, unsigned char flag);
void *recvpackage(void *arg);

int main(int args, char *argv[])
{

	//参数检查
	if (args < 4)
	{
		printf("Usage:shit targetIP startPort endPort\n");
		exit(-1);
	}
	char IP[32]; //目标IP
	strcpy(IP, argv[1]);
	int startPort = atoi(argv[2]);
	int endPort = atoi(argv[3]);
	if ((endPort - startPort) > 60)
	{
		printf("The port range must be within 60 considering your bandwith....\n");
		exit(-1);
	}

	target.sin_family = AF_INET;
	target.sin_addr.s_addr = inet_addr(IP);

	myaddr.sin_family = AF_INET;
	myaddr.sin_port = htons(60000);
	myaddr.sin_addr.s_addr = inet_addr("127.0.0.1");

	//TCP报文的socket
	sockfd = socket(AF_INET, SOCK_RAW, IPPROTO_TCP);

	if (sockfd == -1)
	{
		printf("socket error:%s\n", strerror(errno));
		exit(-1);
	}
	pthread_create(&pth, NULL, recvpackage, NULL);
	int i, count = 1;
	for (i = startPort; i < endPort; i++)
	{
		TCP_Send(i, 2);
	}

	// pthread_join(pth,NULL) ;
	close(sockfd);
	return 0;
}

void TCP_Send(int port, unsigned char flag)
{
	//设置目标端口
	target.sin_port = htons(port);
	//构造包
	char buffer[256];
	memset(buffer, 0, 256);
	struct _tcphdr tcpHeader;
	struct psd_hdr psdHeader;
	//填充TCP
	//目的端口
	tcpHeader.th_dport = htons(port);
	//源端口
	tcpHeader.th_sport = htons(60000);
	//序列号？？
	tcpHeader.th_seq = htonl(0x1245678);
	//确认号
	tcpHeader.th_ack = 0;
	//（4位首部长度/4位保留字）
	tcpHeader.th_lenres = (sizeof(tcpHeader) / 4 << 4 | 0);
	//SYN标志
	tcpHeader.th_flag = flag; //SYN
	//滑动窗口
	tcpHeader.th_win = htons(16384);
	//16位紧急数据偏移量
	tcpHeader.th_urp = 0;
	//16位校验和
	tcpHeader.th_sum = 0;
	//psdheader
	psdHeader.saddr = myaddr.sin_addr.s_addr;
	psdHeader.daddr = target.sin_addr.s_addr;
	psdHeader.mbz = 0;			  // mbz = must be zero, 用于填充对齐
	psdHeader.ptcl = IPPROTO_TCP; //8位协议号
	psdHeader.tcpl = htons(sizeof(tcpHeader));
	//set checksum 使用伪头计算TCP校验和
	memcpy(buffer, &psdHeader, sizeof(psdHeader));
	memcpy(buffer + sizeof(psdHeader), &tcpHeader, sizeof(tcpHeader));
	tcpHeader.th_sum = checksum((unsigned short *)buffer, sizeof(psdHeader) + sizeof(tcpHeader));
	//最终的组包（TCP+IP）
	memcpy(buffer, &tcpHeader, sizeof(tcpHeader));
	//发送的过程   由于IP协议是无连接的协议   所以可以使用sendto
	int ret = sendto(sockfd, buffer, sizeof(tcpHeader), 0, (struct sockaddr *)&target, sizeof(target));
	if (ret == -1)
	{
		printf("send error!:%s\n", strerror(errno));
		exit(-1);
	}
	else
	{
		//printf("send OK\n") ;
	}
}

/*
 * 线程的回调函数
 * */
void *recvpackage(void *args)
{
	//接收的过程recvfrom
	printf("Thread starting...\n");
	struct _tcphdr *testtcp;
	char msg[1024];
	int len = sizeof(myaddr);
	int count, size;
	while (1)
	{
		memset(msg, 0, 1024);
		size = recvfrom(sockfd, msg, sizeof(msg), 0, (struct sockaddr *)&myaddr, &len);
		if (size == -1)
			break;
		//这里的指针是指向IP头部第一个字段的   所以得到TCP头部时要加上相应的偏移量20byte
		testtcp = (struct _tcphdr *)(msg + sizeof(struct _iphdr));
		if (size < (20 + 20))
		{ /*读出的数据小于两个头的最小长度的话continue*/
			continue;
		}
		if (ntohs(testtcp->th_dport) != 60000)
		{
			continue;
		}

		if (testtcp->th_flag == 20)
		{
			// printf("%d port is closed\n",ntohs(testtcp->th_sport)) ;
			continue;
		}
		if (testtcp->th_flag == 18)
		{
			TCP_Send(ntohs(testtcp->th_sport), 4);
			printf("%d port is open！ACK + SYN....\n", ntohs(testtcp->th_sport));
			continue;
		}
	}
}