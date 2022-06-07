#ifndef _RESTORE_SWITCH_H
#define _RESTORE_SWITCH_H

int restore_switch(struct asfd *asfd, struct sbuf *sb,
	const char *fullpath, enum action act,
	struct BFILE *bfd, enum vss_restore vss_restore, struct cntr *cntr,
	const char *encryption_password);

#endif
