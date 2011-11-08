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
	char *cp=NULL;
	char text[64]="";
        char *copy=NULL;
	struct flock fl={F_WRLCK, SEEK_SET, 0, 0, 0};

        // Try to make sure the lock directory exists.
        if(!(copy=strdup(path)))
	{
                logp("Out of memory\n");
		return -1;
	}
	if((cp=strrchr(copy, '/')))
	{
		*cp='\0';
		struct stat statp;
		if(*copy && lstat(copy, &statp))
			mkdir(copy, 0777);
	}
	free(copy);

	if((fdlock=open(path, O_WRONLY|O_CREAT, 0666))<0)
		return -1;
	if(fcntl(fdlock, F_SETLK, &fl)<0)
		return -1;
	snprintf(text, sizeof(text), "%s\n%d\n", progname(), (int)getpid());
	if(write(fdlock, text, strlen(text))!=(ssize_t)strlen(text))
	{
		logp("Could not write progname/pid to %s\n", path);
		return -1;
	}
	fsync(fdlock); // Make sure the pid gets onto the disk.
	// Do not close - closing makes the lock go away.
	//close(fdlock); 
	
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
	struct flock fl;

	if((fdlock=open(path, O_WRONLY, 0666))<0)
		return 0; // file does not exist - could have got the lock
	if(fcntl(fdlock, F_GETLK, &fl)<0)
	{
		// could not have got the lock
		close(fdlock);
		return -1;
	}
	if(fl.l_type==F_UNLCK)
	{
		// Could have got the lock
		close(fdlock);
		return 0;
	}
	close(fdlock);
	// could not have got the lock
	return -1;
#endif
}

static char *read_next_line(FILE *fp)
{
	int dl=0;
	int bl=0;
	char *data=NULL;
	char buf[64]="";

	while(fgets(buf, 64, fp))
	{
		if(data)
		{
			bl=strlen(buf);
			data=(char *)realloc(data, dl+bl+1);
			strncat(data, buf, bl);
		}
		// Most of the time, it will be using the following strdup,
		// which is faster than the realloc/strncat above.
		else data=strdup(buf);
		dl=strlen(data);
		if(data[dl-1]=='\n') break;
	}

	return data;
}

int get_lock_prog_and_pid(const char *path, char **prog)
{
#ifdef HAVE_WIN32
	// On the server only - not supported on Windows.
	return 0;
#else
	int pid=-1;
	FILE *fp=NULL;
	char *data=NULL;
	if(!(fp=fopen(path, "rb"))) return -1;
	if((*prog=read_next_line(fp)))
	{
		char *np=NULL;
		if((np=strrchr(*prog, '\n')))
			*np='\0';
		if((data=read_next_line(fp)))
		{
			pid=atoi(data);
			free(data);
		}
	}
	fclose(fp);
	return pid;
#endif
}
