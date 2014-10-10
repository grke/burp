#ifndef _AUTH_SERVER_H
#define _AUTH_SERVER_H

extern void version_warn(struct asfd *asfd,
	struct conf *globalc, struct conf *cconf);
extern int authorise_server(struct asfd *asfd,
	struct conf *globalc, struct conf *cconf);

#endif
