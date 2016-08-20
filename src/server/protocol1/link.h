#ifndef _LINK_H
#define _LINK_H

#include "conf.h"

extern int recursive_hardlink(const char *src, const char *dst,
	struct conf **confs);
extern int do_link(const char *oldpath, const char *newpath,
	struct stat *statp, struct conf **confs, uint8_t overwrite);

#endif
