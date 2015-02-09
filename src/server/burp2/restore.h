#ifndef _RESTORE_SERVER_BURP2_H
#define _RESTORE_SERVER_BURP2_H

extern int restore_stream_burp2(struct asfd *asfd,
	struct sdirs *sdirs, struct slist *slist,
	struct bu *bu, const char *manifest, regex_t *regex,
	int srestore, struct conf *conf, enum action act,
	enum cntr_status cntr_status);

extern int restore_sbuf_burp2(struct asfd *asfd, struct sbuf *sb,
	enum action act, enum cntr_status cntr_status,
	struct conf *conf, int *need_data);

extern int restore_ent_burp2(struct asfd *asfd,
	struct sbuf **sb,
	struct slist *slist,
	enum action act,
	enum cntr_status cntr_status,
	struct conf *conf,
	int *need_data,
	int *last_ent_was_dir);

#endif
