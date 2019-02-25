#include <unistd.h>
#include <arpa/inet.h>
#include <stdio.h>
#include <stdlib.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <linux/if_ether.h>
#include <linux/in.h>
#include <string.h>
#include <sys/time.h>
#include <fcntl.h>
#include <netinet/in.h>
#include <netinet/ip.h>
#include <netinet/tcp.h>

#define BUFFER_MAX 2048
typedef unsigned char u_char;


// 计算程序运行时间
long compute_time_diff(struct timeval start, struct timeval end);
inline long compute_time_diff(struct timeval start, struct timeval end)
{
	return 1000000 * (end.tv_sec - start.tv_sec) + end.tv_usec - start.tv_usec;
}


int main(int argc, char *argv[])
{
    int h = 0;
    int opt = 0;
    int start_port = 1;
    int end_port = 1;
    char *ip;
    struct timeval start, end;
    while ((opt = getopt(argc, argv, "t:hl:r:")) != -1)
    {
        switch (opt)
        {
        case 't':
            ip = optarg;
            break;
        case 'h':
            h = 1;
            break;
        case 'l':
            start_port = atoi(optarg);
            break;
        case 'r':
            end_port = atoi(optarg);
            break;
        default:
            break;
        }
    }

    if (start_port < 1 || end_port > 65535 || end_port < start_port)
    {
        printf("端口范围出错/n");
        return 0;
    }
    if (h)
    {
        // 半连接方式扫描
        printf("scan %s in half linking mode, port range from %d to %d\n", ip, start_port, end_port);

    }
    else
    {
        // 全连接方式扫描
        // linux socket连接数有上限
        printf("scan %s in full linking mode, port range from %d to %d\n", ip, start_port, end_port);
        gettimeofday(&start, NULL);

        struct sockaddr_in to;

        to.sin_family = AF_INET;
        to.sin_addr.s_addr = inet_addr(ip);

        struct timeval time_out = {1, 0};   //sec, usec
        for (int i = start_port; i <= end_port; i++)
        {
            // printf("%d\n", i);
            int sockfd = socket(AF_INET, SOCK_STREAM, 0);
            fcntl(sockfd, F_SETFL, fcntl(sockfd, F_GETFL)|O_NONBLOCK);
            to.sin_port = htons(i);
            if (connect(sockfd, (struct sockaddr *)&to, sizeof(struct sockaddr)) >= 0)
            {
                printf("port %d in %s is open\n", i, ip);
                close(sockfd);
            }
            else
            {
                fd_set set;
                FD_ZERO(&set);
                FD_SET(sockfd, &set);
                if(select(sockfd + 1, NULL, &set, NULL, &time_out) > 0) // 在超时时间后通过select函数查看socket的状态变化
                {
                    int error;
                    int error_len = sizeof(error);
                    getsockopt(sockfd, SOL_SOCKET, SO_ERROR, &error, &error_len);
                    if(error == 0)
                    {
                        printf("port %d is open\n", i);
                        close(sockfd); 
                    }
                }
            }
            
        }
        gettimeofday(&end, NULL);
        printf("time consumtion: %.2f seconds.\n", ((double)compute_time_diff(start, end)) / 1000000.0);

    }
    return 0;
}