#ifndef _RESTORE_SPOOL_SERVER_BURP2_H
#define _RESTORE_SPOOL_SERVER_BURP2_H

extern int maybe_restore_spool(struct asfd *asfd, const char *manifest,
	struct sdirs *sdirs, struct bu *bu, int srestore, regex_t *regex,
	struct conf *conf, struct slist *slist,
	enum action act, enum cntr_status cntr_status);

#endif

