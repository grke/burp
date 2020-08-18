#ifndef _SERVER_MAIN_H
#define _SERVER_MAIN_H

struct async;

extern int server(struct conf **confs, const char *conffile,
	struct lock *lock, int generate_ca_only);

extern int server_get_working(struct async *mainas);

extern int reload(struct conf **confs, const char *conffile, bool firsttime);

extern void setup_signals(void);

#endif
