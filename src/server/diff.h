#ifndef _DIFF_SERVER_H
#define _DIFF_SERVER_H

extern int do_diff_server(struct asfd *asfd,
	struct sdirs *sdirs, struct conf **confs, enum protocol protocol,
	const char *backup1, const char *backup2);

#endif
