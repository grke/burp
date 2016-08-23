#ifndef __DPTH_PROTOCOL2_H
#define __DPTH_PROTOCOL2_H

#include "../dpth.h"

struct blk;

extern int dpth_protocol2_init(struct dpth *dpth, const char *base_path,
	const char *cname, const char *cfiles, int max_storage_subdirs);

extern int dpth_protocol2_incr_sig(struct dpth *dpth);
extern char *dpth_protocol2_mk(struct dpth *dpth);
extern char *dpth_protocol2_get_save_path(struct dpth *dpth);

extern int dpth_protocol2_fwrite(struct dpth *dpth,
	struct iobuf *iobuf, struct blk *blk);

extern int get_highest_entry(const char *path, int *max, size_t len);

#endif
