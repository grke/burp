#ifndef _AUTOUPGRADE_SERVER_H
#define _AUTOUPGRADE_SERVER_H

extern int autoupgrade_server(struct asfd *asfd,
	long ser_ver, long cli_ver, const char *os, struct conf *conf);

#endif
