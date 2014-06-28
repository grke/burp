#ifndef _BACKUP_PHASE4_SERVER_BURP1_H
#define _BACKUP_PHASE4_SERVER_BURP1_H

extern int do_patch(struct asfd *asfd,
	const char *dst, const char *del, const char *upd,
	bool gzupd, int compression, struct conf *cconf);

extern int backup_phase4_server_burp1(struct sdirs *sdirs, struct conf *cconf);

#endif
