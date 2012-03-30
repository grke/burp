#ifndef _INCEXC_SEND_H
#define _INCEXC_SEND_H

extern int incexc_send_client(struct config *conf, struct cntr *p1cntr);
extern int incexc_send_server(struct config *conf, struct cntr *p1cntr);
extern int incexc_send_server_restore(struct config *conf, struct cntr *p1cntr);

#endif
