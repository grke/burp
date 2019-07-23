#ifndef _RESTORE_CLIENT_PROTOCOL1_H
#define _RESTORE_CLIENT_PROTOCOL1_H

int restore_switch_protocol1(struct asfd *asfd, struct sbuf *sb,
	const char *fullpath, enum action act,
	struct BFILE *bfd, enum vss_restore vss_restore, struct cntr *cntr,
	const char *encryption_password);

#endif
