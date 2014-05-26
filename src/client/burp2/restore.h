#ifndef _RESTORE_CLIENT_H
#define _RESTORE_CLIENT_H

int restore_switch_burp2(struct asfd *asfd, struct sbuf *sb,
	const char *fullpath, enum action act,
	BFILE *bfd, int vss_restore, struct conf *conf);

#endif
