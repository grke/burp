#ifndef _LIST_CLIENT_H
#define _LIST_CLIENT_H

extern void ls_output(char *buf, const char *fname, struct stat *statp);
extern int do_list_client(struct config *conf, enum action act, int json);

#endif // _LIST_CLIENT_H
