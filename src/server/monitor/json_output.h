#ifndef _JSON_OUTPUT_H
#define _JSON_OUTPUT_H

extern int json_send(struct asfd *asfd, 
	struct cstat *clist, struct cstat *cstat,
        struct bu *bu, const char *logfile, const char *browse,
	struct conf **confs);
extern int json_from_statp(const char *path, struct stat *statp);
extern int json_cntr_to_file(struct asfd *asfd, struct cntr *cntr);

extern int json_send_parse_error(struct asfd *asfd, const char *msg);

#endif
