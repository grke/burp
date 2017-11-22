#ifndef _TIMER_SERVER_H
#define _TIMER_SERVER_H

#include "../asfd.h"

extern int run_timer(
	struct asfd *asfd,
	struct sdirs *sdirs,
	struct conf **cconfs);

#ifdef UTEST
extern int run_timer_internal(
        const char *cname,
        struct sdirs *sdirs,
        struct strlist *timer_args,
        char *day_now,
        char *hour_now,
        time_t time_now);
#endif

#endif
