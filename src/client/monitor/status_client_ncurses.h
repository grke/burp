#ifndef STATUS_CLIENT_NCURSES_H
#define STATUS_CLIENT_NCURSES_H

#include "../../action.h"

extern int status_client_ncurses_init(enum action act);
extern int status_client_ncurses(struct conf **confs);

#ifdef UTEST
extern int status_client_ncurses_main_loop(struct async *as,
	const char *orig_client);
#endif

#endif
