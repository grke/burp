#ifndef _SERVER_MAIN_H
#define _SERVER_MAIN_H

extern int init_listen_socket(const char *port, int alladdr);

extern int server(struct conf *conf, const char *conffile,
	struct lock *lock, int generate_ca_only);

extern int reload(struct conf *conf, const char *conffile, int firsttime,
	int oldmax_children, int oldmax_status_children, int json);

extern int setup_signals(int oldmax_children, int max_children,
	int oldmax_status_children, int max_status_children);

#endif
