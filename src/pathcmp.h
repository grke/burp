#ifndef _PATHCMP_H
#define _PATHCMP_H

extern int is_subdir(const char *dir, const char *sub);
extern int pathcmp(const char *a, const char *b);

extern int has_dot_component(const char *path);
extern int is_absolute(const char *path);

#endif
