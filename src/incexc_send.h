#ifndef _INCEXC_SEND_H
#define _INCEXC_SEND_H

extern int incexc_send_client(struct asfd *asfd, struct conf **confs);
extern int incexc_send_server(struct asfd *asfd, struct conf **confs);
extern int incexc_send_server_restore(struct asfd *asfd, struct conf **confs);

#endif
