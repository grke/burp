#include "burp.h"
#include "prog.h"
#include "msg.h"
#include "log.h"

#ifdef HAVE_WIN32
	// Windows version of forkchild is in src/win32/compat/compat.cpp
#else

static pid_t forkchild_fd(int sin, int sout, int serr, const char *path, char * const argv[])
{
	pid_t pid;

	if((pid=fork())==-1) return -1;
	else if(pid==0)
	{
		int fd;
		if((sin>=0 && dup2(sin, STDIN_FILENO)==-1)
		  || (sout>=0 && dup2(sout, STDOUT_FILENO)==-1)
		  || (serr>=0 && dup2(serr, STDERR_FILENO)==-1))
		{
			logp("dup2: %s\n", strerror(errno));
			return -1;
		}
		if(sout>=0) setbuf(stdout, NULL);
		if(serr>=0) setbuf(stderr, NULL);
		/* Close all unused file descriptors before exec.
		 * FD_SETSIZE is not strictly the highest file descriptor-1,
		 * but there does not appear to be a sensible way to find out
		 * the true number, and FD_SETSIZE is a close approximation.
		 * It would be a bit lame if you could open a file whose
		 * descriptor could not be included in an fd_set. */
		for(fd=3; fd<(int)FD_SETSIZE; ++fd) close(fd);
		if(execv(path, argv)==-1)
		{
			logp("execv %s: %s\n", path, strerror(errno));
			return -1;
		}
	}
	return pid;
}

pid_t forkchild(FILE **sin, FILE **sout, FILE **serr, const char *path, char * const argv[])
{
	int sinfds[2], soutfds[2], serrfds[2];
	pid_t pid;

	if((sin && pipe(sinfds)!=0)
	  || (sout && pipe(soutfds)!=0)
	  || (serr && pipe(serrfds)!=0))
		return -1;
	if((sin && !(*sin=fdopen(sinfds[1], "w")))
	  || (sout && !(*sout=fdopen(soutfds[0], "r")))
	  || (serr && !(*serr=fdopen(serrfds[0], "r"))))
		return -1;
	pid=forkchild_fd(sin?sinfds[0]:-1, sout?soutfds[1]:-1,
		serr?serrfds[1]:-1, path, argv);
	if(sin) close(sinfds[0]);
	if(sout) close(soutfds[1]);
	if(serr) close(serrfds[1]);
	return pid;
}

pid_t forkchild_no_wait(FILE **sin, FILE **sout, FILE **serr, const char *path, char * const argv[])
{
	return forkchild(sin, sout, serr, path, argv);
}

#endif
