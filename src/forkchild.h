#ifndef _FORKCHILD_H
#define _FORKCHILD_H

extern pid_t forkchild(FILE **sin, FILE **sout, FILE **serr,
	const char *path, char * const argv[]);

#endif // _CURRENT_BACKUPS_H
