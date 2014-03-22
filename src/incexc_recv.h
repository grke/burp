#ifndef _INCEXC_RECV_H
#define _INCEXC_RECV_H

extern int incexc_recv_client(char **incexc, struct conf *conf);
extern int incexc_recv_server(char **incexc, struct conf *conf);
extern int incexc_recv_client_restore(char **incexc, struct conf *conf);

#endif
