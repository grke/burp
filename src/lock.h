#ifndef LOCK_H
#define LOCK_H

extern int get_lock(const char *path);
extern int test_lock(const char *path);
extern int get_lock_prog_and_pid(const char *path, char **prog);

#endif
