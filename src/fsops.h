#ifndef _FSOPS_H
#define _FSOPS_H

#include <zlib.h>

extern void close_fd(int *fd);
extern int close_fp(FILE **fp);
extern int gzclose_fp(gzFile *fp);

extern int is_dir(const char *path, struct dirent *d);
extern int is_dir_lstat(const char *path);
extern int mkpath(char **rpath, const char *limit);
extern int build_path(const char *datadir, const char *fname,
        char **rpath, const char *limit);
extern int do_rename(const char *oldpath, const char *newpath);
extern int build_path_w(const char *path);
extern int recursive_delete(const char *d, const char *file, uint8_t delfiles);

#endif
