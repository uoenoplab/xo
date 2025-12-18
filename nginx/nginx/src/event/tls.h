#ifndef __XO_TLS_H__
#define __XO_TLS_H__

#include <openssl/err.h>
#include <openssl/ssl.h>
#include <openssl/kdf.h>
#include <openssl/core_names.h>

#include "http_client.h"

//#include "zlog.h"

//extern zlog_category_t *zlog_tls;

int tls_init();
void tls_uninit_ctx(SSL_CTX *ctx);
SSL_CTX *tls_init_ctx(const char *certfile, const char *keyfile);
void tls_free_client(struct http_client *client);
int tls_init_client(SSL_CTX *ctx, struct http_client *client, char *buf, ssize_t size);
int tls_handle_handshake(struct http_client *client, const char *client_data_buffer,
    const ssize_t bytes_received);

#endif
