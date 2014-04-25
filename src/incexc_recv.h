#ifndef _INCEXC_RECV_H
#define _INCEXC_RECV_H

extern int incexc_recv_client(struct async *as,
	char **incexc, struct conf *conf);
extern int incexc_recv_server(struct async *as,
	char **incexc, struct conf *conf);
extern int incexc_recv_client_restore(struct async *as,
	char **incexc, struct conf *conf);

#endif
