#include "burp.h"
#include "forkchild.h"
#include "fzp.h"
#include "log.h"

#ifdef HAVE_WIN32
	// Windows version of forkchild is in src/win32/compat/compat.cpp
#else

static pid_t do_forkchild(int sin, int sout, int serr,
	const char *path, char * const argv[])
{
	pid_t pid;

	if((pid=fork())<0) return -1;
	else if(!pid)
	{
		int fd;
		if((sin>=0 && dup2(sin, STDIN_FILENO)<0)
		  || (sout>=0 && dup2(sout, STDOUT_FILENO)<0)
		  || (serr>=0 && dup2(serr, STDERR_FILENO)<0))
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
		if(execv(path, argv))
			logp("execv %s: %s\n", path, strerror(errno));
		exit(1);
	}
	return pid;
}

pid_t forkchild(struct fzp **sin, struct fzp **sout, struct fzp **serr,
	const char *path, char * const argv[])
{
	pid_t pid;
	int sinfds[2];
	int soutfds[2];
	int serrfds[2];

	if((sin && pipe(sinfds))
	  || (sout && pipe(soutfds))
	  || (serr && pipe(serrfds)))
		return -1;
	if((sin && !(*sin=fzp_dopen(sinfds[1], "w")))
	  || (sout && !(*sout=fzp_dopen(soutfds[0], "r")))
	  || (serr && !(*serr=fzp_dopen(serrfds[0], "r"))))
		return -1;
	pid=do_forkchild(sin?sinfds[0]:-1, sout?soutfds[1]:-1,
		serr?serrfds[1]:-1, path, argv);
	if(sin) close(sinfds[0]);
	if(sout) close(soutfds[1]);
	if(serr) close(serrfds[1]);
	return pid;
}

pid_t forkchild_fd(int *sin, int *sout, int *serr,
	const char *path, char * const argv[])
{
	pid_t pid;
	int sinfds[2];
	int soutfds[2];
	int serrfds[2];

	if((sin && pipe(sinfds))
	  || (sout && pipe(soutfds))
	  || (serr && pipe(serrfds)))
		return -1;
	if(sin) *sin=sinfds[1];
	if(sout) *sout=soutfds[0];
	if(serr) *serr=serrfds[0];
	pid=do_forkchild(sin?sinfds[0]:-1, sout?soutfds[1]:-1,
		serr?serrfds[1]:-1, path, argv);
	if(sin) close(sinfds[0]);
	if(sout) close(soutfds[1]);
	if(serr) close(serrfds[1]);
	return pid;
}

pid_t forkchild_no_wait(struct fzp **sin, struct fzp **sout, struct fzp **serr,
	const char *path, char * const argv[])
{
	return forkchild(sin, sout, serr, path, argv);
}

#endif
