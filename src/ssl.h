#ifndef _BURP_SSL_H
#define _BURP_SSL_H

#include <openssl/ssl.h>
#include "conf.h"

extern int ssl_do_accept(SSL *ssl);
extern SSL_CTX *ssl_initialise_ctx(struct conf **confs);
extern void ssl_destroy_ctx(SSL_CTX *ctx);
extern int ssl_load_dh_params(SSL_CTX *ctx, struct conf **confs);
extern void ssl_load_globals(void);
extern int ssl_check_cert(SSL *ssl, struct conf **confs, struct conf **cconfs);

#endif
