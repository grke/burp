#ifndef _RESTORE_SERVER_H
#define _RESTORE_SERVER_H

extern int do_restore_server(struct async *as, struct sdirs *sdirs,
	enum action act, int srestore,
	char **dir_for_notify, struct conf *conf);

#endif
