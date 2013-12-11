#ifndef _CURRENT_BACKUPS_SERVER_H
#define _CURRENT_BACKUPS_SERVER_H

extern size_t get_librsync_block_len(const char *endfile);

extern int deleteme_move(const char *basedir, const char *fullpath,
	const char *path, struct config *cconf);
extern int deleteme_maybe_delete(struct config *cconf, const char *basedir);

#endif
