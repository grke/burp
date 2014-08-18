#ifndef _JSON_OUTPUT_H
#define _JSON_OUTPUT_H

extern int json_start(struct asfd *asfd);
extern int json_end(struct asfd *asfd);
extern int json_send_summary(struct asfd *asfd, struct cstat *cstat);
extern int json_send_backup_list(struct asfd *asfd,
	struct cstat *clist, struct cstat *cstat);
extern int json_send_zp(struct asfd *asfd, gzFile zp,
	struct cstat *cstat, unsigned long bno, const char *logfile);

#endif
