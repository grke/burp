#ifndef _AUTH_CLIENT_H
#define _AUTH_CLIENT_H

extern int authorise_client(struct asfd *asfd,
	char **server_version,
	const char *cname,
	const char *password,
	struct cntr *cntr);

#endif
