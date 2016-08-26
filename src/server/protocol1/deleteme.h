#ifndef _CURRENT_BACKUPS_SERVER_H
#define _CURRENT_BACKUPS_SERVER_H

extern int deleteme_move(struct sdirs *sdirs, const char *fullpath,
	const char *path);
extern int deleteme_maybe_delete(struct conf **cconfs, struct sdirs *sdirs);

#endif
