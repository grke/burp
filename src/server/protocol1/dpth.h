#ifndef DPTH_PROTOCOL1_H
#define DPTH_PROTOCOL1_H

#include "../dpth.h"

extern int dpth_protocol1_init(struct dpth *dpth, const char *basepath,
	int max_storage_subdirs);

extern int dpth_protocol1_set_from_string(struct dpth *dpth,
	const char *datapath);

extern char *dpth_protocol1_mk(struct dpth *dpth,
	int compression, enum cmd cmd);

#endif
