#ifndef DPTH_PROTOCOL1_H
#define DPTH_PROTOCOL1_H

#include "../dpth.h"

extern int dpthl_init(struct dpth *dpthl, const char *basepath,
	int max_storage_subdirs);

extern int dpthl_set_from_string(struct dpth *dpthl, const char *datapath);
extern char *dpthl_mk(struct dpth *dpthl, int compression, enum cmd cmd);

#endif
