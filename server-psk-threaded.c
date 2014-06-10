/* server-psk-threaded.c
 * A server ecample using a multi-threaded TCP connection with PSK security. 
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

#include <cyassl/ssl.h> /* include cyassl security */
#include <cyassl/options.h> /* included for option sync */
#include <pthread.h>    /* used for concurrent threading */
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
#define LISTENQ     1024
#define SERV_PORT   11111

CYASSL_CTX* ctx; /* global so it's shared by threads */

/* 
 * Fatal error detected, print out and exit. 
 */
void err_sys(const char *err, ...)
{
    printf("Fatal error : %s\n", err);
}

/*
 * Identify which psk key to use.
 */
inline unsigned int my_psk_server_cb(CYASSL* ssl, const char* identity,
                                     unsigned char* key,
                                     unsigned int key_max_len)
{
    (void)ssl;
    (void)key_max_len;

    if (strncmp(identity, "Client_identity", 15) != 0)
        return 0;

    key[0] = 26;
    key[1] = 43;
    key[2] = 60;
    key[3] = 77;

    return 4;
}

/*
 * Process handled by a thread.
 */
void* cyassl_thread(void* fd)
{
    CYASSL* ssl;
    int connfd = (int)fd;
    int  n;             
    char buf[MAXLINE];  
    char response[22] = "I hear ya for shizzle";
   
    memset(buf, 0, MAXLINE);

    /* create CYASSL object */
    if ((ssl = CyaSSL_new(ctx)) == NULL)
        err_sys("CyaSSL_new error");
    CyaSSL_set_fd(ssl, connfd);

    /* respond to client */
    n = CyaSSL_read(ssl, buf, MAXLINE);
    if (n > 0) {
        printf("%s\n", buf);
        if (CyaSSL_write(ssl, response, 22) > 22) {
            err_sys("respond: write error");
        }
    }
    if (n < 0) {
        err_sys("respond: read error");
    }
   
    /* closes the connections after responding */
    CyaSSL_shutdown(ssl);
    CyaSSL_free(ssl);
    if (close(connfd) == -1)
        err_sys("close error"); 
    pthread_exit(NULL);
}

int main()
{
    int                 listenfd, connfd;
    int                 opt;
    struct sockaddr_in  cliAddr, servAddr;
    char                buff[MAXLINE];
    socklen_t           cliLen;
    pthread_t           thread;
    void*               cyassl_thread(void*);
    CyaSSL_Init();

    /* create ctx and configure certificates */
    if ((ctx = CyaSSL_CTX_new(CyaSSLv23_server_method())) == NULL)
        err_sys("CyaSSL_CTX_new error");
    if (CyaSSL_CTX_load_verify_locations(ctx, "certs/ca-cert.pem", 0) != 
                                         SSL_SUCCESS)
        err_sys("Error loading certs/ca-cert.pem, please check the file");
    if (CyaSSL_CTX_use_certificate_file(ctx, "certs/server-cert.pem", 
                                        SSL_FILETYPE_PEM) != SSL_SUCCESS)
        err_sys("Error loading certs/server-cert.pem, please check the file");
    if (CyaSSL_CTX_use_PrivateKey_file(ctx, "certs/server-key.pem",
                                       SSL_FILETYPE_PEM) != SSL_SUCCESS)
        err_sys("Error loading certs/server-key.pem, please check the file");
   
    /* use psk suite for security */ 
    CyaSSL_CTX_set_psk_server_callback(ctx, my_psk_server_cb);
    CyaSSL_CTX_use_psk_identity_hint(ctx, "cyassl server");
    if (CyaSSL_CTX_set_cipher_list(ctx, "PSK-AES128-CBC-SHA256")
                                   != SSL_SUCCESS)
        err_sys("server can't set cipher list");

    /* find a socket */ 
    listenfd = socket(AF_INET, SOCK_STREAM, 0);
    if (listenfd < 0) {
        err_sys("socket error");
    }

    /* set up server address and port */
    memset(&servAddr, 0, sizeof(servAddr));
    servAddr.sin_family      = AF_INET;
    servAddr.sin_addr.s_addr = htonl(INADDR_ANY);
    servAddr.sin_port        = htons(SERV_PORT);

    /* bind to a socket */
    opt = 1;
    setsockopt(listenfd, SOL_SOCKET, SO_REUSEADDR, (const void *)&opt,
               sizeof(int));
    if (bind(listenfd, (struct sockaddr *) &servAddr, sizeof(servAddr)) < 0)
        err_sys("bind error");
    
    /* main loop for accepting and responding to clients */
    for ( ; ; ) {
        /* listen to the socket */   
        if (listen(listenfd, LISTENQ) < 0)
            err_sys("listen error");

        cliLen = sizeof(cliAddr);
        connfd = accept(listenfd, (struct sockaddr *) &cliAddr, &cliLen);
        if (connfd < 0) {
            err_sys("accept error");
            break;
        }
        else {
            printf("Connection from %s, port %d\n",
                   inet_ntop(AF_INET, &cliAddr.sin_addr, buff, sizeof(buff)),
                   ntohs(cliAddr.sin_port));
            pthread_create(&thread, NULL, &cyassl_thread, (void*) connfd);
        }
    }
    /* free up memory used by cyassl */
    CyaSSL_CTX_free(ctx);
    CyaSSL_Cleanup();
    return 0;
}

