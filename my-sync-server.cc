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
#include <openssl/ssl.h>
#include <openssl/err.h>
#include <hiredis/hiredis.h>

using namespace std;

SSL_CTX* g_sslCtx;
redisContext* redisctx;

#define log(...) do { printf(__VA_ARGS__); fflush(stdout); } while(0)

void* app_malloc(int sz, const char *what)
{
    void *vp = OPENSSL_malloc(sz);

    return vp;
}

typedef struct simple_ssl_session_st {
    unsigned char *id;
    unsigned int idlen;
    unsigned char *der;
    int derlen;
    struct simple_ssl_session_st *next;
} simple_ssl_session;

static simple_ssl_session *first = NULL;

static int add_session(SSL *ssl, SSL_SESSION *session)
{
    simple_ssl_session *sess = app_malloc(sizeof(*sess), "get session");
    unsigned char *p;

    SSL_SESSION_get_id(session, &sess->idlen);
    sess->derlen = i2d_SSL_SESSION(session, NULL);
    if (sess->derlen < 0) {
        log("Error encoding session\n");
        OPENSSL_free(sess);
        return 0;
    }

    sess->id = OPENSSL_memdup(SSL_SESSION_get_id(session, NULL), sess->idlen);
    sess->der = app_malloc(sess->derlen, "get session buffer");
    if (!sess->id) {
        log("Out of memory adding to external cache\n");
        OPENSSL_free(sess->id);
        OPENSSL_free(sess->der);
        OPENSSL_free(sess);
        return 0;
    }
    p = sess->der;

    /* Assume it still works. */
    if (i2d_SSL_SESSION(session, &p) != sess->derlen) {
        log("Unexpected session encoding length\n");
        OPENSSL_free(sess->id);
        OPENSSL_free(sess->der);
        OPENSSL_free(sess);
        return 0;
    }

    sess->next = first;
    first = sess;
    log("New session added to external cache...\n");
    log("session id len: %d, session len: %d\n\n", sess->idlen, sess->derlen);
    /* save the session in redis */
    redisReply* reply = redisCommand(redisctx, "SET %b %b", sess->id, sess->idlen, sess->der, sess->derlen);
    log("reply status of saving session into redis: %s\n", reply->str);
    return 0;
}

static SSL_SESSION *get_session(SSL *ssl, const unsigned char *id, int idlen,
                                int *do_copy)
{
    redisReply* reply;
    simple_ssl_session *sess;
    unsigned char *p;
    *do_copy = 0;

    reply = redisCommand(redisctx, "GET %b", id, idlen);
    if(reply->type==REDIS_REPLY_NIL) {
        log("reply type is REDIS_REPLY_NIL: %s\n");
    }
    else if(reply->type==REDIS_REPLY_STRING){
        log("Lookup session: cache hit\n");
        p = reply->str;
        return d2i_SSL_SESSION(NULL, &p, reply->len);
    }
    log("Lookup session: cache miss\n");
    return NULL;
}

static void del_session(SSL_CTX *sctx, SSL_SESSION *session)
{
    simple_ssl_session *sess, *prev = NULL;
    const unsigned char *id;
    unsigned int idlen;
    id = SSL_SESSION_get_id(session, &idlen);
    for (sess = first; sess; sess = sess->next) {
        if (idlen == sess->idlen && !memcmp(sess->id, id, idlen)) {
            if (prev)
                prev->next = sess->next;
            else
                first = sess->next;
            OPENSSL_free(sess->id);
            OPENSSL_free(sess->der);
            OPENSSL_free(sess);
            return;
        }
        prev = sess;
    }
}

static void init_session_cache_ctx(SSL_CTX *sctx)
{
    SSL_CTX_set_session_cache_mode(sctx,
                                   SSL_SESS_CACHE_NO_INTERNAL |
                                   SSL_SESS_CACHE_SERVER);
    SSL_CTX_sess_set_new_cb(sctx, add_session);
    SSL_CTX_sess_set_get_cb(sctx, get_session);
    SSL_CTX_sess_set_remove_cb(sctx, del_session);
}

int main(int argc, char **argv)
{

    /* Connect redis */
    redisctx = redisConnect("172.16.5.20", 6379);
    if(redisctx->err) {
        log("redis connection error: %s\n", redisctx->errstr);
    } else {
        log("redis connection succeed.\n");
    }

    /* Initializing the SSL Library */
    SSL_library_init(); /* load encryption & hash algorithms for SSL */
    SSL_load_error_strings(); /* load the error strings for good error reporting */
    log("SSL Library inited\n");

    /* Creating and Setting Up the SSL Context Structure (SSL_CTX) */
    // g_sslCtx = SSL_CTX_new(SSLv23_method());
    g_sslCtx = SSL_CTX_new(TLSv1_2_method());  /* session id not supported from tls 1.3 */
    long mode = SSL_CTX_get_session_cache_mode(g_sslCtx);
    log("SSL_CTX session mode: %ld.\n", mode);
    init_session_cache_ctx(g_sslCtx);
    log("Initialize SSL Context to use external session caching.\n");

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

