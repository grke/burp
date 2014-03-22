#ifndef LOCK_H
#define LOCK_H

enum lockstat
{
	GET_LOCK_NOT_GOT=0,
	GET_LOCK_ERROR,
	GET_LOCK_GOT
};

struct lock
{
	int fd;
	enum lockstat status;
	char *path;
};

extern struct lock *lock_alloc(void);
extern int lock_init(struct lock *lock, const char *path);
extern struct lock *lock_alloc_and_init(const char *path);
extern void lock_free(struct lock **lock);

// Need to test lock->status to find out what happened when calling these.
extern void lock_get_quick(struct lock *lock);
extern void lock_get(struct lock *lock);

extern int lock_test(const char *path);
extern int lock_release(struct lock *lock);

// Nothing to do with locks.
extern int looks_like_tmp_or_hidden_file(const char *filename);

#endif
