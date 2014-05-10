#ifndef CA_SERVER_H
#define CA_SERVER_H

extern int ca_server_setup(struct conf *conf);

extern int ca_server_maybe_sign_client_cert(struct asfd *asfd,
	struct conf *conf, struct conf *cconf);

#endif
