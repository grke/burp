#ifndef _DIFF_CLIENT_H
#define _DIFF_CLIENT_H

extern int do_diff_client(struct asfd *asfd,
	enum action act, int json, struct conf **confs);

#endif
