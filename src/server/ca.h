#ifndef CA_SERVER_H
#define CA_SERVER_H

extern int ca_server_setup(struct conf **confs);

extern int ca_server_maybe_sign_client_cert(struct asfd *asfd,
	struct conf **confs, struct conf **cconfs);

extern int ca_x509_verify_crl(struct conf **confs,
	X509 *peer_cert, const char *ssl_peer_cn);

#endif
