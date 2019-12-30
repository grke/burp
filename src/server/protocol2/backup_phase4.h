#ifndef _BACKUP_PHASE4_SERVER_PROTOCOL2_H
#define _BACKUP_PHASE4_SERVER_PROTOCOL2_H

#include "../../fzp.h"
#include "../../lock.h"
#include "../../sbuf.h"

struct hooks
{
	char *path;
	uint64_t *fingerprints;
	size_t len;
};

extern int backup_phase4_server_protocol2(struct sdirs *sdirs,
	struct conf **confs);
// Never call regenerate_client_dindex() outside of backup phases 2 to 4!
extern int regenerate_client_dindex(struct sdirs *sdirs);
extern int merge_dindexes(const char *dst, const char *srca, const char *srcb);
extern int merge_files_in_dir(const char *final,
	const char *fmanifest, const char *srcdir, uint64_t fcount,
	int merge(const char *dst, const char *src, const char *srcb));
extern int merge_files_in_dir_no_fcount(const char *final,
	const char *fmanifest,
	int merge(const char *dst, const char *srca, const char *srcb));

extern int merge_into_global_sparse(const char *sparse, const char *global,
	struct lock *lock);

#ifdef UTEST
extern void hooks_free(struct hooks **hooks);
extern int hooks_gzprintf(struct fzp *fzp, struct hooks *hooks);
extern int merge_sparse_indexes(const char *dst,
	const char *srca, const char *srcb);
extern int dindex_gzprintf(struct fzp *fzp, uint64_t *dindex);
extern int get_next_set_of_hooks(struct hooks **hnew, struct sbuf *sb,
	struct fzp *spzp, char **path, uint64_t **fingerprints, size_t *len);
#endif

extern int remove_backup_from_global_sparse(const char *global_sparse,
	const char *candidate_str);

#endif
