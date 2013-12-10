#ifndef _LIST_SERVER_H
#define _LIST_SERVER_H

extern int check_browsedir(const char *browsedir,
	char **path, size_t bdlen, char **last_bd_match);
extern int do_list_server(struct sdirs *sdirs, struct config *conf,
	const char *backup, const char *listregex, const char *browsedir);

#endif
