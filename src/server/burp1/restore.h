#ifndef _RESTORE_SERVER_BURP1_H
#define _RESTORE_SERVER_BURP1_H

int restore_burp1(struct asfd *asfd, struct bu *bu,
	const char *manifest, regex_t *regex, int srestore,
	enum action act, struct sdirs *sdirs, enum cntr_status cntr_status,
	struct conf *cconf);

#endif
