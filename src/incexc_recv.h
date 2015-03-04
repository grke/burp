#ifndef _INCEXC_RECV_H
#define _INCEXC_RECV_H

extern int incexc_recv_client(struct asfd *asfd,
	char **incexc, struct conf **confs);
extern int incexc_recv_server(struct asfd *asfd,
	char **incexc, struct conf **confs);
extern int incexc_recv_client_restore(struct asfd *asfd,
	char **incexc, struct conf **confs);

#endif
