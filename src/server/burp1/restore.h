#ifndef _RESTORE_SERVER_BURP1_H
#define _RESTORE_SERVER_BURP1_H

extern int restore_sbuf_burp1(struct asfd *asfd, struct sbuf *sb,
	struct bu *bu, enum action act, struct sdirs *sdirs,
	enum cntr_status cntr_status, struct conf *cconf);

#endif
