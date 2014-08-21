#ifndef _JSON_OUTPUT_H
#define _JSON_OUTPUT_H

extern int json_send_zp(struct asfd *asfd, gzFile zp,
	struct cstat *cstat, unsigned long bno, const char *logfile);

extern int json_send(struct asfd *asfd, 
	struct cstat *clist, struct cstat *cstat);

#endif
