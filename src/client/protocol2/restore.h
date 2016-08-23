#ifndef _RESTORE_CLIENT_PROTOCOL2_H
#define _RESTORE_CLIENT_PROTOCOL2_H

struct sbuf;

int restore_switch_protocol2(struct asfd *asfd, struct sbuf *sb,
	const char *fullpath, enum action act,
	struct BFILE *bfd, int vss_restore, struct cntr *cntr);

#endif
