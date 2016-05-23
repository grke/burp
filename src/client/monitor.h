#ifndef _MONITOR_CLIENT_H
#define _MONITOR_CLIENT_H

extern int do_monitor_client(struct asfd *asfd);

#ifdef UTEST
extern int monitor_client_main_loop(struct async *as);
#endif

#endif
