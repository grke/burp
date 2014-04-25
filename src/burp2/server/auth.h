#ifndef _AUTH_SERVER_H
#define _AUTH_SERVER_H

extern void version_warn(struct async *as,
	struct conf *conf, struct conf *cconf);
extern int authorise_server(struct async *as,
	struct conf *conf, struct conf *cconf);

#endif
