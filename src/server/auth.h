#ifndef _AUTH_SERVER_H
#define _AUTH_SERVER_H

extern void version_warn(struct asfd *asfd,
	struct conf **globalcs, struct conf **cconfs);
extern int authorise_server(struct asfd *asfd,
	struct conf **globalcs, struct conf **cconfs);

#endif
