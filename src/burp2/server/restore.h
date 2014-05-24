#ifndef _RESTORE_SERVER_H
#define _RESTORE_SERVER_H

extern int do_restore_server(struct asfd *asfd, struct sdirs *sdirs,
	enum action act, int srestore,
	char **dir_for_notify, struct conf *conf);

// Burp1 restore can use these until there is a bit more unification.
extern int srestore_matches(struct strlist *s, const char *path);
extern int check_srestore(struct conf *conf, const char *path);


#endif
