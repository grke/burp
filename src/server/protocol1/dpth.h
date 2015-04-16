#ifndef DPTH_PROTOCOL1_H
#define DPTH_PROTOCOL1_H

#include "../dpth.h"

extern int dpthl_init(struct dpth *dpthl,
	const char *basepath, struct conf **cconfs);

extern int dpthl_incr(struct dpth *dpthl, struct conf **cconfs);
extern int dpthl_set_from_string(struct dpth *dpthl, const char *datapath);
extern char *dpthl_mk(struct dpth *dpthl, struct conf **cconfs, enum cmd cmd);

#endif
