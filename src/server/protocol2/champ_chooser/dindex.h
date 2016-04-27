#ifndef _DINDEX_H
#define _DINDEX_H

extern int delete_unused_data_files(struct sdirs *sdirs, int resume);

#ifdef UTEST
extern int compare_dindexes_and_unlink_datafiles(const char *dindex_old,
	const char *dindex_new, const char *datadir);
#endif

#endif
