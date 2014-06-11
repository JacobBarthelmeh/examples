/* server-psk.c
 * A server ecample using a TCP connection with PSK security. 
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

#include <cyassl/ssl.h>     /* include CyaSSL security */
#include <cyassl/options.h> /* included for options sync */
#include <sys/socket.h>
#include <netinet/in.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <errno.h>
#include <arpa/inet.h>

#define MAXLINE     4096
#define LISTENQ     1024
#define SERV_PORT   11111

const char* cert        = "certs/ca-cert.pem";
const char* cert_server = "certs/server-cert.pem";

/* 
 * Fatal error detected, print out and exit. 
 */
void err_sys(const char *err, ...)
{
    printf("Fatal error : %s\n", err);
}

/* 
 * Handles response to client.
 */
void respond(CYASSL* ssl)
{
    int  n;              /* length of string read */
    char buf[MAXLINE];   /* string read from client */
    char response[22] = "I hear ya for shizzle";
    memset(buf, 0, MAXLINE);
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
}

/*
 * Identify which psk key to use.
 */
unsigned int my_psk_server_cb(CYASSL* ssl, const char* identity, unsigned char* key,
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

int main()
{
    int                 listenfd, connfd;
    int                 opt;
    struct sockaddr_in  cliAddr, servAddr;
    char                buff[MAXLINE];
    socklen_t           cliLen;

    CyaSSL_Init();
    
    /* create ctx and configure certificates */
    CYASSL_CTX* ctx;
    if ((ctx = CyaSSL_CTX_new(CyaSSLv23_server_method())) == NULL)
        err_sys("CyaSSL_CTX_new error");
    if (CyaSSL_CTX_load_verify_locations(ctx, cert, 0) != SSL_SUCCESS)
        err_sys("Error loading certs/ca-cert.pem, please check the file");
    if (CyaSSL_CTX_use_certificate_file(ctx, cert_server, SSL_FILETYPE_PEM) != SSL_SUCCESS)
        err_sys("Error loading certs/server-cert.pem, please check the file");
    if (CyaSSL_CTX_use_PrivateKey_file(ctx, cert_server, SSL_FILETYPE_PEM) != SSL_SUCCESS)
        err_sys("Error loading certs/server-key.pem, please check the file");
   
    /* use psk suite for security */ 
    CyaSSL_CTX_set_psk_server_callback(ctx, my_psk_server_cb);
    CyaSSL_CTX_use_psk_identity_hint(ctx, "cyassl server");
    if (CyaSSL_CTX_set_cipher_list(ctx, "PSK-AES128-CBC-SHA256")
                                   != SSL_SUCCESS)
        err_sys("server can't set cipher list");


    /* set up server address and port */
    memset(&servAddr, 0, sizeof(servAddr));
    servAddr.sin_family      = AF_INET;
    servAddr.sin_addr.s_addr = htonl(INADDR_ANY);
    servAddr.sin_port        = htons(SERV_PORT);

    /* find a socket */ 
    listenfd = socket(AF_INET, SOCK_STREAM, 0);
    if (listenfd < 0) {
        err_sys("socket error");
    }

    /* bind to a socket */
    opt = 1;
    setsockopt(listenfd, SOL_SOCKET, SO_REUSEADDR, (const void *)&opt,
               sizeof(int));
    if (bind(listenfd, (struct sockaddr *) &servAddr, sizeof(servAddr)) < 0)
        err_sys("bind error");
    
    
    /* main loop for accepting and responding to clients */
    for ( ; ; ) {
        /* listen to the socket */   
        if (listen(listenfd, LISTENQ) < 0) {
            err_sys("listen error");
            break;
        }
        
        cliLen = sizeof(cliAddr);
        CYASSL* ssl;
        connfd = accept(listenfd, (struct sockaddr *) &cliAddr, &cliLen);
        if (connfd < 0) {
            err_sys("accept error");
            break;
        }
        else {
            printf("Connection from %s, port %d\n",
                   inet_ntop(AF_INET, &cliAddr.sin_addr, buff, sizeof(buff)),
                   ntohs(cliAddr.sin_port));
            
            /* create CYASSL object and respond */
            if ((ssl = CyaSSL_new(ctx)) == NULL) {
                err_sys("CyaSSL_new error");
                break;
            }
            CyaSSL_set_fd(ssl, connfd);
            respond(ssl);
            
            /* closes the connections after responding */
            CyaSSL_shutdown(ssl);
            CyaSSL_free(ssl);
            
            if (close(connfd) == -1) {
                err_sys("close error");
                break;
            }
        }
    }
    /* free up memory used by CyaSSL */
    CyaSSL_CTX_free(ctx);
    CyaSSL_Cleanup();
    return 0;
}

