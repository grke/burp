#ifndef _AUTH_SERVER_H
#define _AUTH_SERVER_H

#include "asfd.h"
#include "conf.h"

extern void version_warn(struct asfd *asfd,
	struct conf **globalcs, struct conf **cconfs);
extern int authorise_server(struct asfd *asfd,
	struct conf **globalcs, struct conf **cconfs);

#ifdef UTEST
extern int check_passwd(const char *passwd, const char *plain_text);
#endif

#endif
