/* epoll-ssl.c
 *
 * A server ecample using epoll with SSL on a TCP connection.
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
#include <fcntl.h>
#include <sys/epoll.h>

#include <cyassl/ssl.h>
#include <cyassl/options.h>
#include <stdint.h>


#define svrCert    "certs/server-cert.pem"
#define svrKey     "certs/server-key.pem"
#define MAXLINE     4096
#define LISTENQ     1024
#define SERV_PORT   11111

struct client_ssl {
    CYASSL*   ssl;
    int       fd;
    uint32_t u32;
    int     status;
} client_ssl;

int numCon   = 0;
CYASSL_CTX*  ctx;

/*
 * Handles response to client.
 */
int respond(struct epoll_event povent, int epollfd)
{
    int  n;              /* length of string read */
    char buf[MAXLINE];   /* string read from client */
    struct client_ssl* info = povent.data.ptr;
    int sockfd = info->fd;

    CyaSSL_accept(info->ssl);
    CyaSSL_get_error(info->ssl, 0);

    memset(buf, 0, MAXLINE);
    n = CyaSSL_read(info->ssl, buf, MAXLINE);
    if (n > 0) {
        printf("%s\n", buf);
        if (CyaSSL_write(info->ssl, buf, strlen(buf)) != strlen(buf)) {
            printf("write error");
        }
    }
    if (n < 0) {
        if (errno != EAGAIN) {
            printf("respond: read error\n");
            numCon--;
            CyaSSL_shutdown(info->ssl);
            CyaSSL_free(info->ssl);
            free(info);
            epoll_ctl(epollfd, EPOLL_CTL_DEL, sockfd, &povent);
            printf("disconected client that had error\n");
            return 1;
        }
        return 0;
    }
    if (n == 0) {
        numCon--;
        CyaSSL_shutdown(info->ssl);
        CyaSSL_free(info->ssl);
        free(info);
        epoll_ctl(epollfd, EPOLL_CTL_DEL, sockfd, &povent);
        printf("a client has disconected\n");
    }

    return 0;
}

int accept_process(struct epoll_event povent, int epollfd, int listenfd)
{
    socklen_t           cliLen;
    struct sockaddr_in  cliAddr;
    int connfd;
    char                buff[MAXLINE];
    struct client_ssl*  info;

    cliLen = sizeof(cliAddr);
    connfd = accept(listenfd, (struct sockaddr *) &cliAddr, &cliLen);
    if (connfd < 0) {
        printf("accept error\n");
        return 1;
    }
    else {
        printf("Connection from %s, port %d\n",
              inet_ntop(AF_INET, &cliAddr.sin_addr, buff, sizeof(buff)),
               ntohs(cliAddr.sin_port));
        if (fcntl(connfd, F_SETFL, O_NONBLOCK) < 0) {
            printf("Fatal error : fcntl set failed\n");
            return 1;
        }

        /* add fd to epoll */
        info = malloc(sizeof(struct client_ssl));
        if (info == NULL) {
            printf("Error creating memory space with malloc!\n");
            return 1;
        }
        info->u32 = EPOLLIN;
        info->fd  = connfd;
        /* create CYASSL object */
        if ((info->ssl = CyaSSL_new(ctx)) == NULL) {
            printf("Fatal error : CyaSSL_new error\n");
            return 1;
        }
        CyaSSL_set_fd(info->ssl, info->fd);
        CyaSSL_set_using_nonblock(info->ssl, 1);

        povent.data.ptr = info;
        if (epoll_ctl(epollfd, EPOLL_CTL_ADD, connfd, &povent) == -1) {
            printf("Error adding new fd\n");
            return 1;
        }

        numCon++;
    }

    return 0;
}

int main()
{
    int listenfd, epollfd, nfds;
    int opt, i;
    struct sockaddr_in  servAddr;
    struct epoll_event  povent, event[10];

    CyaSSL_Init();

    if ((ctx = CyaSSL_CTX_new(CyaSSLv23_server_method())) == NULL) {
        printf("Fatal error : CyaSSL_CTX_new error\n");
        return 1;
    }

    if (CyaSSL_CTX_use_certificate_file(ctx, svrCert, SSL_FILETYPE_PEM)
                != SSL_SUCCESS) {
        printf("Error loading server cert file\n");
        return 1;
    }

    if (CyaSSL_CTX_use_PrivateKey_file(ctx, svrKey, SSL_FILETYPE_PEM)
                != SSL_SUCCESS) {
        printf("Error loading server key file\n");
        return 1;
    }

    if (CyaSSL_CTX_set_cipher_list(ctx, "AES128-SHA256")
        != SSL_SUCCESS) {
        printf("Fatal error : server can't set cipher list\n");
        return 1;
    }

    /* find a socket , 0 for using TCP option */
    listenfd = socket(AF_INET, SOCK_STREAM, 0);
    if (listenfd < 0) {
        printf("socket error\n");
        return 1;
    }

    /* set up server address and port */
    memset(&servAddr, 0, sizeof(servAddr));
    servAddr.sin_family      = AF_INET;
    servAddr.sin_addr.s_addr = htonl(INADDR_ANY);
    servAddr.sin_port        = htons(SERV_PORT);

    /* bind to a socket */
    opt = 1;
    setsockopt(listenfd, SOL_SOCKET, SO_REUSEADDR, (const void*)&opt,
               sizeof(int));
    if (bind(listenfd, (struct sockaddr *) &servAddr, sizeof(servAddr)) < 0) {
        printf("bind error");
        return 1;
    }

    /* listen to the socket */
    if (listen(listenfd, LISTENQ) < 0) {
        printf("listen error");
        return 1;
    }

    /* create epoll event */
    epollfd = epoll_create(10);
    if (epollfd == -1) {
        printf("Error on epoll create\n");
        return 1;
    }

    povent.events = EPOLLIN;
    povent.data.fd = listenfd;
    if (epoll_ctl(epollfd, EPOLL_CTL_ADD, listenfd, &povent) == -1) {
        printf("Error adding listen fd to epoll\n");
        return 1;
    }

    /* main loop for accepting and responding to clients */
    for ( ; ; ) {
        nfds = epoll_wait(epollfd, event, 10, -1);
        if (nfds == -1) {
            printf("Error on epoll wait\n");
            return 1;
        }

        /* run through all fd's and events */
        for (i = 0; i < nfds; ++i) {
            if (event[i].data.fd == listenfd) {
                accept_process(povent, epollfd, listenfd);
            }
            else {
                respond(event[i], epollfd);
            }
        }

    }

    /* closes the connections after responding */
    if (close(epollfd) == -1) {
        printf("close error");
        return 1;
    }

    return 0;
}

