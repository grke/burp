#ifndef _BACKUP_PHASE4_SERVER_H
#define _BACKUP_PHASE4_SERVER_H

struct sdirs;

extern int do_patch(const char *dst, const char *del, const char *upd,
	bool gzupd, int compression);

extern int backup_phase4_server_all(struct sdirs *sdirs,
	struct conf **cconfs);

#endif
