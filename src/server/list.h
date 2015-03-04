#ifndef _LIST_SERVER_H
#define _LIST_SERVER_H

extern int check_browsedir(const char *browsedir,
	struct sbuf *mb, size_t bdlen, char **last_bd_match);
extern int do_list_server(struct asfd *asfd,
	struct sdirs *sdirs, struct conf **confs,
	const char *backup, const char *listregex, const char *browsedir);

#endif
