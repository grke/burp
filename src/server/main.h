#ifndef _SERVER_MAIN_H
#define _SERVER_MAIN_H

#include "conf.h"
#include "lock.h"

#include <stdbool.h>

extern int server(struct conf **confs, const char *conffile,
	struct lock *lock, int generate_ca_only);

extern int reload(struct conf **confs, const char *conffile, bool firsttime,
	int oldmax_children, int oldmax_status_children);

extern void setup_signals(void);

#endif
