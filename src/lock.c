#include "burp.h"
#include "lock.h"
#include "log.h"
#include "handy.h"

int get_lock(const char *path)
{
#ifdef HAVE_WIN32
	// Would somebody please tell me how to get a lock on Windows?!
	return 0;
#else
	int fdlock;
	char pid[16]="";

	if((fdlock=open(path, O_WRONLY|O_CREAT, 0666))==-1)
		return -1;
	if(lockf(fdlock, F_TLOCK, 0))
		return -1;
	snprintf(pid, sizeof(pid), "%d\n", (int)getpid());
	if(write(fdlock, pid, strlen(pid))!=(ssize_t)strlen(pid))
	{
		logp("Could not write pid to %s\n", path);
		return -1;
	}
	fsync(fdlock); // Make sure the pid gets onto the disk.
	
	return 0;
#endif
}

int test_lock(const char *path)
{
#ifdef HAVE_WIN32
	// Would somebody please tell me how to test a lock on Windows?!
	return 0;
#else
	int fdlock;

	if((fdlock=open(path, O_WRONLY, 0666))<0)
		return 0; // file does not exist - could have got the lock
	if(lockf(fdlock, F_TLOCK, 0) && (errno==EAGAIN || errno==EACCES))
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

int get_lock_pid(const char *path)
{
#ifdef HAVE_WIN32
	// On the server only - not supported on Windows.
	return 0;
#else
	int fd;
	int pid=-1;
	char buf[16]="";
	if((fd=open(path, O_RDONLY))<0) return -1;
	if(read(fd, buf, sizeof(buf))>0)
		pid=atoi(buf);
	close(fd);
	return pid;
#endif
}
