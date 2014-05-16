/* server-tcp.c
 * A server ecample using a TCP connection. 
 *  
 * This file is part of CyaSSL.
 *
 * CyaSSL is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2 of the License, or
 * (at your option) any later version.
 *
 * CyaSSL is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA 02110-1301, USA
 */

#include <sys/socket.h>
#include <netinet/in.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <errno.h>
#include <arpa/inet.h>
#include <signal.h>

#define MAXLINE     4096
#define TCP         0
#define SA struct   sockaddr
#define LISTENQ     1024
#define SERV_PORT   11111

/* 
 * Fatal error detected, print out and exit. */
void
err_sys(const char *err, ...)
{
    printf("Fatal error : %s\n", err);
    exit(1);
}

/* 
 * Handles response to client.
 */
void
respond(int sockfd)
{
    int  n;              /* length of string read */
    char buf[MAXLINE];   /* string read from client */
    n = read(sockfd, buf, MAXLINE);
    if(n > 0){
        printf("%s\n", buf);
        char response[22] = "I hear ya for shizzle";
        if(write(sockfd, response, 22) > 22){
            err_sys("write error");
        }
    }

    if(n < 0){
        err_sys("respond: read error");
    }
}

/*
 *Listen to the socket. 
 */
void
lstn(int listenfd, int backlog)
{
    char* ptr;
    if( (ptr = getenv("LISTENQ")) != NULL)
        backlog = atoi(ptr);
    
    if(listen(listenfd, backlog) < 0)
        err_sys("listen error");
}

int
main(int argc, char** argv)
{
    int                 listenfd, connfd;
    struct sockaddr_in  cliaddr, servaddr;
    char                buff[MAXLINE];
    socklen_t           clilen;

    /* find a socket */ 
    listenfd = socket(AF_INET, SOCK_STREAM, TCP);
    if(listenfd < 0){
        err_sys("socket error");
    }

    /* set up server address and port */
    bzero(&servaddr, sizeof(servaddr));
    servaddr.sin_family      = AF_INET;
    servaddr.sin_addr.s_addr = htonl(INADDR_ANY);
    servaddr.sin_port        = htons(SERV_PORT);

    /* bind to a socket */
    if(bind(listenfd, (SA *) &servaddr, sizeof(servaddr)) < 0)
        err_sys("bind error");
    
    /* listen to the socket */   
    lstn(listenfd, LISTENQ);
    
    /* main loop for accepting and responding to clients */
    for ( ; ; ) {
        clilen = sizeof(cliaddr);
        connfd = accept(listenfd, (SA *) &cliaddr, &clilen);
        if(connfd < 0){
            if(errno != EINTR){
                err_sys("accept error");
            }
        }
        else{
            printf("Connection from %s, port %d\n",
                inet_ntop(AF_INET, &cliaddr.sin_addr, buff, sizeof(buff)),
                ntohs(cliaddr.sin_port));
            respond(connfd);
            /* closes the connections after responding */
            if(close(connfd) == -1)
                err_sys("close error");
        }
    }
}

