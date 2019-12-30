#ifndef _CLIST_H
#define _CLIST_H

extern int get_client_list(
	struct cstat **clist,
	const char *cdir,
	struct conf **conf
);
extern void clist_free(
	struct cstat **clist
);

#endif
