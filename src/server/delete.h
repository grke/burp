#ifndef _DELETE_SERVER_H
#define _DELETE_SERVER_H

extern int delete_backup(struct sdirs *sdirs, struct conf **cconfs,
	struct bu *arr, int a, int b);
extern int delete_backups(struct sdirs *sdirs, struct conf **cconfs);

extern int do_delete_server(struct asfd *asfd,
	struct sdirs *sdirs, struct conf **confs, const char *backup);

#endif
