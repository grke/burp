#ifndef _RESTORE_CLIENT_BURP1_H
#define _RESTORE_CLIENT_BURP1_H

int restore_switch_burp1(struct asfd *asfd, struct sbuf *sb,
	const char *fullpath, enum action act,
	struct BFILE *bfd, int vss_restore, struct conf *conf);

#endif
