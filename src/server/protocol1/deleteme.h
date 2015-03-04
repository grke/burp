#ifndef _CURRENT_BACKUPS_SERVER_H
#define _CURRENT_BACKUPS_SERVER_H

extern int deleteme_move(const char *basedir, const char *fullpath,
	const char *path, struct conf **cconfs);
extern int deleteme_maybe_delete(struct conf **cconfs, const char *basedir);

#endif
