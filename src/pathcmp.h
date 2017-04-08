#ifndef _PATHCMP_H
#define _PATHCMP_H

extern int is_subdir(const char *dir, const char *sub);
extern int is_not_absolute(const char *path, const char *err_msg);
extern int pathcmp(const char *a, const char *b);


#endif
