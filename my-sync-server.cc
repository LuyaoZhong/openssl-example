#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <netinet/in.h>
#include <fcntl.h>
#include <netdb.h>
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <unistd.h>
#include <errno.h>
#include <string>
#include <poll.h>
#include <sys/epoll.h>
#include <signal.h>
#include <openssl/bio.h>
#include <openssl/ssl.h>
#include <openssl/err.h>

using namespace std;

SSL_CTX* g_sslCtx;

#define log(...) do { printf(__VA_ARGS__); fflush(stdout); } while(0)

int main(int argc, char **argv)
{
    /* Initializing the SSL Library */
    SSL_library_init(); /* load encryption & hash algorithms for SSL */
    SSL_load_error_strings(); /* load the error strings for good error reporting */
    log("ssl inited\n");

    /* Creating and Setting Up the SSL Context Structure (SSL_CTX) */
    g_sslCtx = SSL_CTX_new(SSLv23_method());
    long mode = SSL_CTX_get_session_cache_mode(g_sslCtx);
    log("SSL_CTX session mode: %ld.\n", mode);

    /* Setting Up the Certificate and Key */
    string cert = "server.pem", key = "server.pem";
    SSL_CTX_use_certificate_file(g_sslCtx, cert.c_str(), SSL_FILETYPE_PEM);
    SSL_CTX_use_PrivateKey_file(g_sslCtx, key.c_str(), SSL_FILETYPE_PEM);
    SSL_CTX_check_private_key(g_sslCtx);

    /* Setting Up the TCP/IP Connection */
    int listen_sock;
    listen_sock = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
    struct sockaddr_in sa_serv;
    memset(&sa_serv, 0, sizeof(sa_serv));
    sa_serv.sin_family      = AF_INET;
    sa_serv.sin_addr.s_addr = INADDR_ANY;
    sa_serv.sin_port        = htons(443);      /* Server Port number */

    bind(listen_sock, (struct sockaddr*)&sa_serv,sizeof(sa_serv));
    listen(listen_sock, 20);
    log("listen at port 443...\n");

    for(;;) {
        /* Establishing a TCP/IP Connection (on the SSL Server) */
        struct sockaddr_in sa_cli;
        socklen_t client_len = sizeof(sa_cli);
        int sock = accept(listen_sock, (struct sockaddr*)&sa_cli, &client_len);
        log("Accept a connect from [%s:%d]\n",
            inet_ntoa(sa_cli.sin_addr), ntohs(sa_cli.sin_port));

        /* Creating and Setting Up the SSL Structure */
        SSL* ssl = SSL_new(g_sslCtx);

        /* Performing an SSL Handshake with SSL_read and SSL_write */
        SSL_set_fd(ssl, sock);
        SSL_set_accept_state(ssl);
        char buf[4096];
        SSL_read(ssl, buf, sizeof buf);
        const char* resp = "HTTP/1.1 200 OK\r\nConnection: Close\r\n\r\n";
        SSL_write(ssl, resp, strlen(resp));
        log("send response %ld bytes to client\n", strlen(resp));

        SSL_shutdown(ssl);
        SSL_free(ssl);
        close(sock);
    }

    SSL_CTX_free(g_sslCtx);
    close(listen_sock);
    return 0;
}

