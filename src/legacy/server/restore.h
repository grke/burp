#ifndef _RESTORE_SERVER_LEGACY_H
#define _RESTORE_SERVER_LEGACY_H

extern int do_patch(const char *dst, const char *del, const char *upd,
	bool gzupd, int compression, struct conf *cconf);
extern int do_restore_server_legacy(struct sdirs *sdirs, enum action act,
	int srestore, char **dir_for_notify, struct conf *cconf);

#endif
