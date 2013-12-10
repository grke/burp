#ifndef CA_SERVER_H
#define CA_SERVER_H

extern int ca_server_setup(struct config *conf);

extern int ca_server_maybe_sign_client_cert(struct config *conf,
	struct config *cconf);

#endif
