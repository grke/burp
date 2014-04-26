#ifndef _RESTORE_SERVER_BURP1_H
#define _RESTORE_SERVER_BURP1_H

extern int do_patch(struct async *as,
	const char *dst, const char *del, const char *upd,
	bool gzupd, int compression, struct conf *cconf);
extern int do_restore_server_burp1(struct async *as,
	struct sdirs *sdirs, enum action act,
	int srestore, char **dir_for_notify, struct conf *cconf);

#endif
