#include <openssl/ssl.h>
#include <openssl/bio.h>
#include <openssl/err.h>
#include <openssl/engine.h>

#include <arpa/inet.h>
#include <sys/socket.h>
#include <netinet/in.h>

#include <stdio.h>
#include <memory.h>
#include <unistd.h>

#define LISTEN_PORT 23333

int main(int argc, char **argv) {
    int err = 0;
    const SSL_METHOD *meth = NULL;
    SSL_CTX *ctx = NULL;
    SSL *ssl = NULL;

    int listen_sock = -1;
    int client_sock = -1;
    struct sockaddr_in sa_serv;
    struct sockaddr_in sa_cli;

    BIO *sbio = NULL;
    char rbuf[1024];
    int connected = 0;

    fd_set read_set;
    fd_set write_set;
    struct timeval timeout;
    int ret = 0;
    size_t numfds = 0;
    OSSL_ASYNC_FD *async_fds = NULL;

    ENGINE *ssl_server_engine = NULL;

    memset(&rbuf, 0, sizeof(rbuf));
    if (!SSL_library_init()) {
        printf("SSL lib init failed\n");
        return -1;
    }
    SSL_load_error_strings();

    // meth = TLSv1_method();
    meth = SSLv23_method();
    ctx = SSL_CTX_new(meth);

    ssl_server_engine = ENGINE_by_id("dasync");
    if (!ENGINE_set_default(ssl_server_engine, ENGINE_METHOD_ALL)) {
        printf("failed to set default engine\n");
        ERR_print_errors_fp(stderr);
        return -1;
    }


    // load the server cert, when will send to the client
    if (!SSL_CTX_use_certificate_file(ctx, "server.pem", SSL_FILETYPE_PEM)) {
        printf("can't load cert file\n");
        return -1;
    };
    // load the private key, which is used to unencript the data which encript with public key in the server cert by the client.
    if (!SSL_CTX_use_PrivateKey_file(ctx, "server.pem", SSL_FILETYPE_PEM)) {
        printf("can't load private key file\n");
        return -1;
    };

    // SSL_VERIFY_NONE means the server doesn't verify the client cert, only the client verify the server cert
    SSL_CTX_set_verify(ctx, SSL_VERIFY_NONE, NULL);
    SSL_CTX_set_mode(ctx, SSL_MODE_ASYNC);

    ssl = SSL_new(ctx);

    listen_sock = socket(PF_INET, SOCK_STREAM, IPPROTO_TCP);

    if (listen_sock < 0) {
        printf("create socket failed\n");
        return -1;
    }

    memset(&sa_serv, 0, sizeof(sa_serv));
    sa_serv.sin_family      = AF_INET;
    sa_serv.sin_addr.s_addr = INADDR_ANY;
    sa_serv.sin_port        = htons(LISTEN_PORT);      /* Server Port number */

    err = bind(listen_sock, (struct sockaddr*)&sa_serv, sizeof(sa_serv));

    if (err < 0) {
        printf("Bind failed\n");
        return -1;
    }

    err = listen(listen_sock, 20);
    if (err < 0) {
        printf("listen failed\n");
        return -1;
    }

    socklen_t sa_cli_size = sizeof(sa_cli);
    client_sock = accept(listen_sock, (struct sockaddr *)&sa_cli, &sa_cli_size);
    printf("Accept connect from %x, port %x\n", sa_cli.sin_addr.s_addr, sa_cli.sin_port);
    int maxfd = client_sock;

    FD_ZERO(&read_set);
    FD_ZERO(&write_set);
    FD_SET(client_sock, &read_set);
    timeout.tv_sec = 3000;
    timeout.tv_usec = 0;

    sbio = BIO_new_socket(client_sock, BIO_NOCLOSE);
    SSL_set_bio(ssl, sbio, sbio);

    while (1) {
        printf("waiting on select\n");

        ret = select(maxfd + 1, &read_set, NULL, NULL, &timeout);
        printf("select maxfd is %d\n", maxfd);

        if (ret < 0) {
            printf("selected failed\n");
            break;
        }
        if (ret == 0) {
            printf("select timeout\n");
            timeout.tv_sec = 10;
            timeout.tv_usec - 0;
            FD_SET(client_sock, &read_set);
            continue;
        }

        for (int i = 0; i < maxfd + 1; i++) {
            if (FD_ISSET(i, &read_set)) {
                printf("the client socket is readable\n");
    
                if (!connected) {
                    err = SSL_accept(ssl);
                    if (err < 0) {
                        err = SSL_get_error(ssl, err);
                        if (err == SSL_ERROR_WANT_ASYNC) {
                            printf("ssl async handshake\n");
                            if (!SSL_get_all_async_fds(ssl, NULL, &numfds)) {

                                printf("get all async fds failed\n");
                                return -1;
                            }
                            if (numfds == 0) {
                                continue;
                            }
                            printf("get %ld async fds\n", numfds);
                            if (async_fds != NULL) {
                                free(async_fds);
                            }
                            async_fds = malloc(sizeof(OSSL_ASYNC_FD) & numfds);
                            if (!SSL_get_all_async_fds(ssl, async_fds, &numfds)) {
                                printf("get all async fds failed\n");
                                free(async_fds);
                                async_fds = NULL;
                                return -1;
                            }
                            // disable write stdin, we want to finish the handshake
                            FD_ZERO(&read_set);
                            FD_ZERO(&write_set);
                            for (int j = 0; j < numfds; j++) {
                                if (async_fds[j] > maxfd)
                                    maxfd = async_fds[j];
                                FD_SET(async_fds[j], &read_set);
                                printf("set async fd %d to read_set\n", async_fds[j]);
                            }
                            FD_SET(client_sock, &read_set);
                            if (client_sock > maxfd) {
                                maxfd = client_sock;
                                printf("update maxfd %d\n", maxfd);
                            }
                            printf("set all async fds\n");
                            continue;
                        }
                        printf("ssl handshake failed\n");
                        ERR_print_errors_fp(stderr);
                        return -1;
                    }
    
                    printf("SSL handshake successful\n");
                    connected = 1;
                    //FD_ZERO(&write_set);
                    //FD_ZERO(&read_set);
                    //FD_SET(0, &read_set);
                    //maxfd = 0;
                    // cleanup the async fds;
                    //free(async_fds);
                    //async_fds = NULL;
                    //numfds = 0;
                    continue;
                }
                printf("already connected, and ready to read\n"); 
                ret = SSL_read(ssl, rbuf, sizeof(rbuf) - 1);
                if (ret <= 0) {
                    ret = SSL_get_error(ssl, ret);
                    printf("ssl read error %d", ret);
                    if (ret == SSL_ERROR_ZERO_RETURN) {
                        printf("the connection is closed\n");
                    }
                    break;
                }
                rbuf[ret + 1] = '\0';
                printf("recv: %s\n", rbuf);
            }
            if (FD_ISSET(i, &write_set)) {
                printf("the client socket is writable\n");
            }
        }
    }

    close(client_sock);
    close(listen_sock);
    return 0;

}

