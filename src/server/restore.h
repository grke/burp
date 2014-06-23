#ifndef _RESTORE_SERVER_H
#define _RESTORE_SERVER_H

extern int restore_end(struct asfd *asfd, struct conf *conf);
extern int check_srestore(struct conf *conf, const char *path);

extern int do_restore_server(struct asfd *asfd, struct sdirs *sdirs,
	enum action act, int srestore,
	char **dir_for_notify, struct conf *conf);

#endif
