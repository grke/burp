#ifndef _AUTOUPGRADE_SERVER_H
#define _AUTOUPGRADE_SERVER_H

extern int autoupgrade_server(struct async *as,
	long ser_ver, long cli_ver, const char *os, struct conf **confs);

#endif
