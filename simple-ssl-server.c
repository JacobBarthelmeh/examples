/* simple ssl server
 *
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
#include <cyassl/test.h> 

#define MAXLINE     4096

int main(int argc, char** argv)
{
    int         n;              /* length of string read */
    char        buf[MAXLINE];   /* string read from client */
    int         listenfd, connfd;
    CYASSL_CTX* ctx;
    CYASSL*     ssl;
    struct func_args arg;

    arg.argc = argc;
    arg.argv = argv;

    CyaSSL_Init();
    
    /* create ctx and configure certificates */
    if ((ctx = CyaSSL_CTX_new(CyaSSLv23_server_method())) == NULL)
        err_sys("Fatal error : CyaSSL_CTX_new error");
   
    if (CyaSSL_CTX_use_certificate_file(ctx, svrCert, SSL_FILETYPE_PEM)
                != SSL_SUCCESS)
        err_sys("can't load server cert file,"
                    "Please run from CyaSSL home dir");

    if (CyaSSL_CTX_use_PrivateKey_file(ctx, svrKey, SSL_FILETYPE_PEM)
                != SSL_SUCCESS)
        err_sys("can't load server key file, "
                    "Please run from CyaSSL home dir");
        
    tcp_accept(&listenfd, &connfd, &arg, yasslPort, 1, 0);
        
    if (connfd < 0) {
        err_sys("Fatal error : accept error");
    }
    else {
        /* create CYASSL object and respond */
        if ((ssl = CyaSSL_new(ctx)) == NULL)
            err_sys("Fatal error : CyaSSL_new error");
  
        CyaSSL_set_fd(ssl, connfd);

	    memset(buf, 0, MAXLINE);
	    n = CyaSSL_read(ssl, buf, MAXLINE + 1);
	    if (n > 0) {
	        buf[n - 1] = '\0';
	        printf("%s\n", buf);
	        if (CyaSSL_write(ssl, buf, strlen(buf)) > strlen(buf))
	            err_sys("Fatal error : respond: write error");
	    }

	    if (n < 0)
	        err_sys("Fatal error :respond: read error");
            
        /* closes the connections after responding */
        CyaSSL_shutdown(ssl);
        CyaSSL_free(ssl);

        if (close(listenfd) == -1 && close(connfd) == -1)
            err_sys("Fatal error : close error");
    }
    
    /* free up memory used by CyaSSL */
    CyaSSL_CTX_free(ctx);
    CyaSSL_Cleanup();

    return 0;
}

