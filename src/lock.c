#include "burp.h"
#include "lock.h"
#include "log.h"
#include "handy.h"

// Return 0 for lock got, 1 for lock not got, -1 for error.
int get_lock(const char *path)
{
#if defined(HAVE_WIN32) || !defined(HAVE_LOCKF)
	// Would somebody please tell me how to get a lock on Windows?!
	return 0;
#else
	int fdlock;
	char *cp=NULL;
	char text[64]="";
        char *copy=NULL;

        // Try to make sure the lock directory exists.
        if(!(copy=strdup(path)))
	{
                logp("Out of memory\n");
		return -1;
	}
	if((cp=strrchr(copy, '/')))
	{
		*cp='\0';
		if(*copy) mkdir(copy, 0777);
	}
	free(copy);

	if((fdlock=open(path, O_WRONLY|O_CREAT, 0666))==-1)
		return -1;
	if(lockf(fdlock, F_TLOCK, 0))
	{
		if(errno==EACCES || errno==EAGAIN)
			return 1; // Lock not got.
		logp("Could not get lock %s: %s\n", path, strerror(errno));
		return -1; // Some other error.
	}
	snprintf(text, sizeof(text), "%d\n%s\n", (int)getpid(), progname());
	if(write(fdlock, text, strlen(text))!=(ssize_t)strlen(text))
	{
		logp("Could not write pid/progname to %s\n", path);
		return -1;
	}
	fsync(fdlock); // Make sure the pid gets onto the disk.
	//close(fdlock);
	
	return 0;
#endif
}

int test_lock(const char *path)
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
