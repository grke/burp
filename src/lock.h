#ifndef LOCK_H
#define LOCK_H

// Return 0 for lock got, 1 for lock not got, -1 for error.	
extern int get_lock(const char *path);
extern int test_lock(const char *path);

extern int looks_like_tmp_or_hidden_file(const char *filename);

#endif
