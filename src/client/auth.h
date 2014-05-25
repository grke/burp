#ifndef _AUTH_CLIENT_H
#define _AUTH_CLIENT_H

extern int authorise_client(struct asfd *asfd,
	struct conf *conf, char **server_version);

#endif
