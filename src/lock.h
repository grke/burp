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
	struct lock *next;
};

extern struct lock *lock_alloc(void);
extern int lock_init(struct lock *lock, const char *path);
extern struct lock *lock_alloc_and_init(const char *path);
extern void lock_free(struct lock **lock);
extern int lock_write_pid(struct lock *lock);

// Need to test lock->status to find out what happened when calling these.
extern void lock_get_quick(struct lock *lock);
extern void lock_get(struct lock *lock);

extern int lock_test(const char *path);
extern int lock_release(struct lock *lock);

extern void lock_add_to_list(struct lock **locklist, struct lock *lock);
extern void locks_release_and_free(struct lock **locklist);

#endif
