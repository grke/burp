#ifndef __HANDY_H
#define __HANDY_H

extern FILE *file_open(const char *path, const char *mode);
extern int file_close(FILE **fp);

extern int mkpath(char **rpath, const char *limit);
extern int pathcmp(const char *a, const char *b);
extern int build_path_w(const char *path);

#endif
