#ifndef _LIST_SERVER_H
#define _LIST_SERVER_H

struct sbuf;
struct sdirs;

extern int list_server_init(
	struct asfd *a,
	struct sdirs *s,
	struct conf **c,
	const char *backup_str,
	const char *regex_str,
	const char *browsedir_str);
extern int do_list_server(void);
extern void list_server_free(void);

extern int check_browsedir(const char *browsedir,
	struct sbuf *mb,
	size_t bdlen,
	char **last_bd_match);

#ifdef UTEST
extern void maybe_fake_directory(struct sbuf *mb);
extern int do_list_server_work(
	int list_server_callback(const char *fullpath));
#endif

#endif
