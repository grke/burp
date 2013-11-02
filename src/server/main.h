#ifndef _SERVER_MAIN_H
#define _SERVER_MAIN_H

extern int server(struct config *conf, const char *configfile,
	int generate_ca_only);

extern int reload(struct config *conf, const char *configfile, bool firsttime,
	int oldmax_children, int oldmax_status_children);

extern int setup_signals(int oldmax_children, int max_children,
	int oldmax_status_children, int max_status_children);

#endif
