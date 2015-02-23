#ifndef _LINK_H
#define _LINK_H

extern int recursive_hardlink(const char *src, const char *dst,
	struct conf *conf);
extern int do_link(const char *oldpath, const char *newpath,
	struct stat *statp, struct conf *conf, uint8_t overwrite);

#endif
