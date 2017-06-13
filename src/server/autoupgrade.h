#ifndef _AUTOUPGRADE_SERVER_H
#define _AUTOUPGRADE_SERVER_H

extern int autoupgrade_server(struct asfd *asfd,
	long ser_ver, long cli_ver, const char *os, struct cntr *cntr,
	const char *autoupgrade_dir);

#endif
