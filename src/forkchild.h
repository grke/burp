#ifndef _FORKCHILD_H
#define _FORKCHILD_H

struct fzp;

extern pid_t forkchild(struct fzp **sin,
	struct fzp **sout, struct fzp **serr,
	const char *path, char * const argv[]);
extern pid_t forkchild_fd(int *sin,
	int *sout, int *serr,
        const char *path, char * const argv[]);
extern pid_t forkchild_no_wait(struct fzp **sin,
	struct fzp **sout, struct fzp **serr,
	const char *path, char * const argv[]);

#endif
