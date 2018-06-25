#ifndef _RESTORE_SERVER_H
#define _RESTORE_SERVER_H

#include "../regexp.h"

extern int do_restore_server(struct asfd *asfd, struct sdirs *sdirs,
	enum action act, int srestore,
	char **dir_for_notify, struct conf **confs);

#endif
