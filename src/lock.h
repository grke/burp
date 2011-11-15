#ifndef LOCK_H
#define LOCK_H

extern int get_lock(const char *path);
extern int test_lock(const char *path);

#endif
