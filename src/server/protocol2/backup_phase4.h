#ifndef _BACKUP_PHASE4_SERVER_PROTOCOL2_H
#define _BACKUP_PHASE4_SERVER_PROTOCOL2_H

extern int backup_phase4_server_protocol2(struct sdirs *sdirs,
	struct conf **confs);
extern int regenerate_client_dindex(struct sdirs *sdirs);
extern int merge_dindexes(const char *dst, const char *srca, const char *srcb);
extern int merge_files_in_dir(const char *final,
	const char *fmanifest, const char *srcdir, uint64_t fcount,
	int merge(const char *dst, const char *src, const char *srcb));
extern int merge_files_in_dir_no_fcount(const char *final,
	const char *fmanifest, const char *srcdir,
	int merge(const char *dst, const char *srca, const char *srcb));

#ifdef UTEST
extern int merge_sparse_indexes(const char *dst,
	const char *srca, const char *srcb);
extern int gzprintf_dindex(struct fzp *fzp, uint64_t *dindex);
#endif

extern int remove_from_global_sparse(const char *global_sparse,
	const char *candidate_str);

#endif
