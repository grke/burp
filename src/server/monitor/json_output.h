#ifndef _JSON_OUTPUT_H
#define _JSON_OUTPUT_H

extern int json_send(struct asfd *asfd, 
	struct cstat *clist, struct cstat *cstat,
        struct bu *bu, const char *logfile, const char *browse,
	struct conf *conf);
extern int json_from_sbuf(struct sbuf *sb);

#endif
