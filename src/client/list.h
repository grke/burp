#ifndef _LIST_CLIENT_H
#define _LIST_CLIENT_H

extern void ls_output(char *buf, const char *fname, struct stat *statp);
extern int do_list_client(struct asfd *asfd,
	enum action act, int json, struct conf *conf);

#endif
