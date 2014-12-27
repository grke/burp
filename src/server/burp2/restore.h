#ifndef _RESTORE_SERVER_BURP2_H
#define _RESTORE_SERVER_BURP2_H

int restore_burp2(struct asfd *asfd, struct bu *bu,
	const char *manifest, regex_t *regex, int srestore,
	enum action act, struct sdirs *sdirs, enum cntr_status cntr_status,
	struct conf *conf);

#endif
