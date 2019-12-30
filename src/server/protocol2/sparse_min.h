#ifndef _SPARSE_MIN_H
#define _SPARSE_MIN_H

extern int sparse_minimise(
	struct conf **conf,
	const char *global_sparse,
	struct lock *sparse_lock,
	struct cstat *clist
);

#endif
