#include "burp.h"
#include "alloc.h"
#include "lock.h"
#include "log.h"

struct lock *lock_alloc(void)
{
	return (struct lock *)calloc_w(1, sizeof(struct lock), __func__);
}

int lock_init(struct lock *lock, const char *path)
{
	free_w(&lock->path);
	if(!(lock->path=strdup_w(path, __func__)))
		return -1;
	return 0;
}

struct lock *lock_alloc_and_init(const char *path)
{
	struct lock *lock;
	if(!(lock=lock_alloc()) || lock_init(lock, path))
		lock_free(&lock);
	return lock;
}

static void lock_free_content(struct lock *lock)
{
	free_w(&lock->path);
}

void lock_free(struct lock **lock)
{
	if(!lock || !*lock) return;
	lock_free_content(*lock);
	free_v((void **)lock);
}

void lock_get_quick(struct lock *lock)
{
#if defined(HAVE_WIN32) || !defined(HAVE_LOCKF)
	// Would somebody please tell me how to get a lock on Windows?!
	lock->status=GET_LOCK_GOT;
	return;
#else
	if((lock->fd=open(
		lock->path,
#ifdef O_NOFOLLOW
		O_NOFOLLOW|
#endif
		O_WRONLY|O_CREAT,
		0666
	))<0)
	{
		logp("Could not open lock file %s: %s\n",
			lock->path, strerror(errno));
		goto error;
	}
	if(lockf(lock->fd, F_TLOCK, 0))
	{
		if(errno==EACCES || errno==EAGAIN)
			goto notgot;
		logp("Could not get lock %s: %s\n",
			lock->path, strerror(errno));
		goto error; // Some other error.
	}
	if(lock_write_pid(lock))
		goto error;
	
	lock->status=GET_LOCK_GOT;
	return;
error:
	lock->status=GET_LOCK_ERROR;
	return;
notgot:
	lock->status=GET_LOCK_NOT_GOT;
	return;
#endif
}

int lock_write_pid(struct lock *lock)
{
	char text[64]="";
	if(ftruncate(lock->fd, 0))
	{
		logp("Could not ftruncate lock %s: %s\n",
			lock->path, strerror(errno));
		return -1;
	}
	if(lseek(lock->fd, 0, SEEK_SET)<0)
	{
		logp("Could not seek to start of lock %s: %s\n",
			lock->path, strerror(errno));
		return -1;
	}
	snprintf(text, sizeof(text), "%d\n", (int)getpid());
	if(write(lock->fd, text, strlen(text))!=(ssize_t)strlen(text))
	{
		logp("Could not write pid/progname to %s: %s\n",
			lock->path, strerror(errno));
		return -1;
	}
	return 0;
}

// Return 0 for lock got, 1 for lock not got, -1 for error.
void lock_get(struct lock *lock)
{
#if defined(HAVE_WIN32) || !defined(HAVE_LOCKF)
	// Would somebody please tell me how to get a lock on Windows?!
	lock->status=GET_LOCK_GOT;
	return;
#else
	char *cp=NULL;
        char *copy=NULL;

        // Try to make sure the lock directory exists.
        if(!(copy=strdup_w(lock->path, __func__)))
	{
		lock->status=GET_LOCK_ERROR;
		return;
	}
	if((cp=strrchr(copy, '/')))
	{
		*cp='\0';
		if(*copy) mkdir(copy, 0777);
	}
	free_w(&copy);

	lock_get_quick(lock);

	// Try to make sure the pid gets onto the disk.
	if(lock->status==GET_LOCK_GOT) fsync(lock->fd);
	return;
#endif
}

int lock_test(const char *path)
{
#if defined(HAVE_WIN32) || !defined(HAVE_LOCKF)
	// Would somebody please tell me how to test a lock on Windows?!
	return 0;
#else
	int r=0;
	int fdlock;

	if((fdlock=open(path, O_WRONLY, 0666))<0)
		return 0; // file does not exist - could have got the lock
	errno=0;
	if((r=lockf(fdlock, F_TLOCK, 0)) && (errno==EAGAIN || errno==EACCES))
	{
		// could not have got the lock
		close(fdlock);
		return -1;
	}
	close(fdlock);
	// could have got the lock
	return 0;
#endif
}

int lock_release(struct lock *lock)
{
	int ret=0;
	if(!lock || lock->status!=GET_LOCK_GOT) return 0;
	if(lock->path) unlink(lock->path);
	if(lock->fd>=0)
	{
		if((ret=close(lock->fd)))
			logp("Could not close %s: %s\n",
				lock->path, strerror(errno));
		lock->fd=-1;
	}
	lock->status=GET_LOCK_NOT_GOT;
	return ret;
}

void lock_add_to_list(struct lock **locklist, struct lock *lock)
{
	if(*locklist) lock->next=*locklist;
	*locklist=lock;
}

void locks_release_and_free(struct lock **locklist)
{
	struct lock *l;
	struct lock *head;
	if(!locklist) return;
	head=*locklist;
	while(head)
	{
		l=head;
		head=head->next;
		lock_release(l);
		lock_free(&l);
	}
	*locklist=NULL;
}
