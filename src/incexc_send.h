#ifndef _INCEXC_SEND_H
#define _INCEXC_SEND_H

extern int incexc_send_client(struct async *as, struct conf *conf);
extern int incexc_send_server(struct async *as, struct conf *conf);
extern int incexc_send_server_restore(struct async *as, struct conf *conf);

#endif
