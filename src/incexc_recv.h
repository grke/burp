#ifndef _INCEXC_RECV_H
#define _INCEXC_RECV_H

extern int incexc_recv_client(char **incexc,
	struct config *conf, struct cntr *p1cntr);
extern int incexc_recv_server(char **incexc,
	struct config *conf, struct cntr *p1cntr);
extern int incexc_recv_client_restore(char **incexc,
	struct config *conf, struct cntr *p1cntr);
extern int incexc_recv_client_quota(char **incexc,
	struct config *conf, struct cntr *p1cntr);

#endif
