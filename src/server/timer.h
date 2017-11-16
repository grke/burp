#ifndef _TIMER_SERVER_H
#define _TIMER_SERVER_H

#include "../asfd.h"

extern int run_timer(
	struct asfd *asfd,
	struct sdirs *sdirs,
	struct conf **cconfs);

#endif
