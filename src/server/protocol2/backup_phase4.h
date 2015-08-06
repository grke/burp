#ifndef _BACKUP_PHASE4_SERVER_PROTOCOL2_H
#define _BACKUP_PHASE4_SERVER_PROTOCOL2_H

extern int backup_phase4_server_protocol2(struct sdirs *sdirs,
	struct conf **confs);

#ifdef UTEST
extern int merge_sparse_indexes(const char *dst,
	const char *srca, const char *srcb);
extern int merge_files_in_dir(const char *final, const char *fmanifest,
	const char *srcdir, uint64_t fcount,
	int merge(const char *dst, const char *src, const char *srcb));
#endif

#endif
