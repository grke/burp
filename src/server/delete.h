#ifndef _DELETE_SERVER_H
#define _DELETE_SERVER_H

extern int delete_backups(struct asfd *asfd, struct sdirs *sdirs,
	struct conf *cconf);

extern int do_delete_server(struct asfd *asfd,
	struct sdirs *sdirs, struct conf *conf, const char *backup);

#endif
