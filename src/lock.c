#include "include.h"

struct lock *lock_alloc(void)
{
	struct lock *lock=NULL;
	if(!(lock=(struct lock *)calloc(1, sizeof(struct lock))))
		log_out_of_memory(__func__);
	return lock;
}

int lock_init(struct lock *lock, const char *path)
{
	if(lock->path) free(lock->path);
	if(!(lock->path=strdup(path)))
	{
		log_out_of_memory(__func__);
		return -1;
	}
	return 0;
}

struct lock *lock_alloc_and_init(const char *path)
{
	struct lock *lock;
	if(!(lock=lock_alloc()) || lock_init(lock, path))
		lock_free(&lock);
	return lock;
}

void lock_free(struct lock **lock)
{
	if(!lock || !*lock) return;
	if((*lock)->path) free((*lock)->path);
	free(*lock);
	*lock=NULL;
}

void lock_get_quick(struct lock *lock)
{
#if defined(HAVE_WIN32) || !defined(HAVE_LOCKF)
	// Would somebody please tell me how to get a lock on Windows?!
	lock->status=GET_LOCK_GOT;
	return;
#else
	char text[64]="";

	if((lock->fd=open(lock->path, O_WRONLY|O_CREAT, 0666))<0)
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
	snprintf(text, sizeof(text), "%d\n%s\n", (int)getpid(), progname());
	if(write(lock->fd, text, strlen(text))!=(ssize_t)strlen(text))
	{
		logp("Could not write pid/progname to %s\n", lock->path);
		goto error;
	}
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
        if(!(copy=strdup(lock->path)))
	{
                log_out_of_memory(__func__);
		lock->status=GET_LOCK_ERROR;
		return;
	}
	if((cp=strrchr(copy, '/')))
	{
		*cp='\0';
		if(*copy) mkdir(copy, 0777);
	}
	free(copy);

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

// FIX THIS:
// In this source file so that both bedup and status_server can see it.
int looks_like_tmp_or_hidden_file(const char *filename)
{
	if(!filename) return 0;
	if(filename[0]=='.' // Also avoids '.' and '..'.
	// I am told that emacs tmp files end with '~'.
	  || filename[strlen(filename)-1]=='~')
		return 1;
	return 0;
}
