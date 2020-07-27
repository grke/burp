#ifndef _DELETE_SERVER_H
#define _DELETE_SERVER_H

struct sdirs;

extern int delete_backups(struct sdirs *sdirs, const char *cname,
	struct strlist *keep, const char *manual_delete);

extern int do_delete_server(struct asfd *asfd,
	struct sdirs *sdirs, struct conf **conf,
	const char *cname, const char *backup, const char *manual_delete);

#endif
