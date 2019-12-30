#include "../../burp.h"
#include "../../alloc.h"
#include "../../bu.h"
#include "../../cmd.h"
#include "../../cstat.h"
#include "../../fsops.h"
#include "../../fzp.h"
#include "../../lock.h"
#include "../../log.h"
#include "../../prepend.h"
#include "../../protocol2/blk.h"
#include "../../sbuf.h"
#include "../../strlist.h"
#include "../../server/bu_get.h"
#include "../../server/manio.h"
#include "../../server/sdirs.h"
#include "champ_chooser/champ_chooser.h"
#include "backup_phase4.h"
#include "clist.h"
#include "sparse_min.h"

static int hookscmp(struct hooks *a, struct hooks *b)
{
	size_t i;
	uint64_t *af=a->fingerprints;
	uint64_t *bf=b->fingerprints;
	for(i=0; i<a->len && i<b->len; i++)
	{
		if(af[i]>bf[i]) return 1;
		if(af[i]<bf[i]) return -1;
	}
	if(a->len>b->len) return 1;
	if(a->len<b->len) return -1;
	return 0;
}

static int hooks_alloc(struct hooks **hnew,
	char **path, uint64_t **fingerprints, size_t *len)
{
	if(!*path || !*fingerprints) return 0;

	if(!(*hnew=(struct hooks *)malloc_w(sizeof(struct hooks), __func__)))
		return -1;
	
	(*hnew)->path=*path;
	(*hnew)->fingerprints=*fingerprints;
	(*hnew)->len=*len;
	*path=NULL;
	*fingerprints=NULL;
	*len=0;
	return 0;
}

// Return 0 for OK, -1 for error, 1 for finished reading the file.
#ifndef UTEST
static
#endif
int get_next_set_of_hooks(struct hooks **hnew, struct sbuf *sb,
	struct fzp *spzp, char **path, uint64_t **fingerprints, size_t *len)
{
	struct blk blk;
	while(1)
	{
		switch(sbuf_fill_from_file(sb, spzp, NULL))
		{
			case -1: goto error;
			case 1:
				// Reached the end.
				if(hooks_alloc(hnew, path, fingerprints, len))
					goto error;
				return 1;
		}
		if(sb->path.cmd==CMD_MANIFEST)
		{
			if(hooks_alloc(hnew, path, fingerprints, len))
				break;
			*path=sb->path.buf;
			sb->path.buf=NULL;
			sbuf_free_content(sb);
			if(*hnew) return 0;
		}
		else if(sb->path.cmd==CMD_FINGERPRINT)
		{
			if(!(*fingerprints=(uint64_t *)realloc_w(*fingerprints,
				((*len)+1)*sizeof(uint64_t), __func__)))
					goto error;
			if(blk_set_from_iobuf_fingerprint(&blk, &sb->path))
				goto error;
			(*fingerprints)[(*len)++]=blk.fingerprint;
			sbuf_free_content(sb);
		}
		else
		{
			iobuf_log_unexpected(&sb->path, __func__);
			break;
		}
	}

error:
	sbuf_free_content(sb);
	return -1;
}

#ifndef UTEST
static
#endif
int hooks_gzprintf(struct fzp *fzp, struct hooks *hooks)
{
	size_t i;
	fzp_printf(fzp, "%c%04lX%s\n", CMD_MANIFEST,
		strlen(hooks->path), hooks->path);
	for(i=0; i<hooks->len; i++)
		if(to_fzp_fingerprint(fzp, hooks->fingerprints[i]))
			return -1;
	return 0;
}

#ifndef UTEST
static
#endif
void hooks_free(struct hooks **hooks)
{
	if(!*hooks) return;
	free_w(&(*hooks)->path);
	free_v((void **)&(*hooks)->fingerprints);
	free_v((void **)hooks);
}

/* Merge two files of sorted sparse indexes into each other. */
#ifndef UTEST
static
#endif
int merge_sparse_indexes(const char *dst, const char *srca, const char *srcb)
{
	int fcmp;
	int ret=-1;
	struct sbuf *asb=NULL;
	struct sbuf *bsb=NULL;
	uint64_t *afingerprints=NULL;
	uint64_t *bfingerprints=NULL;
	size_t aflen=0;
	size_t bflen=0;
	struct fzp *azp=NULL;
	struct fzp *bzp=NULL;
	struct fzp *dzp=NULL;
	struct hooks *anew=NULL;
	struct hooks *bnew=NULL;
	char *apath=NULL;
	char *bpath=NULL;

	if(!(asb=sbuf_alloc(PROTO_2))
	  || (srcb && !(bsb=sbuf_alloc(PROTO_2))))
		goto end;
	if(build_path_w(dst))
		goto end;
	if((srca && !(azp=fzp_gzopen(srca, "rb")))
	  || (srcb && !(bzp=fzp_gzopen(srcb, "rb")))
	  || !(dzp=fzp_gzopen(dst, "wb")))
		goto end;

	while(azp || bzp || anew || bnew)
	{
		if(azp
		  && asb
		  && !anew)
		{
			switch(get_next_set_of_hooks(&anew, asb, azp,
				&apath, &afingerprints, &aflen))
			{
				case -1: goto end;
				case 1: fzp_close(&azp); // Finished OK.
			}
		}

		if(bzp
		  && bsb
		  && !bnew)
		{
			switch(get_next_set_of_hooks(&bnew, bsb, bzp,
				&bpath, &bfingerprints, &bflen))
			{
				case -1: goto end;
				case 1: fzp_close(&bzp); // Finished OK.
			}
		}

		if(anew && !bnew)
		{
			if(hooks_gzprintf(dzp, anew)) goto end;
			hooks_free(&anew);
		}
		else if(!anew && bnew)
		{
			if(hooks_gzprintf(dzp, bnew)) goto end;
			hooks_free(&bnew);
		}
		else if(!anew && !bnew)
		{
			continue;
		}
		else if(!(fcmp=hookscmp(anew, bnew)))
		{
			// They were the same - write the new one.
			if(hooks_gzprintf(dzp, bnew)) goto end;
			hooks_free(&anew);
			hooks_free(&bnew);
		}
		else if(fcmp<0)
		{
			if(hooks_gzprintf(dzp, anew)) goto end;
			hooks_free(&anew);
		}
		else
		{
			if(hooks_gzprintf(dzp, bnew)) goto end;
			hooks_free(&bnew);
		}
	}

	if(fzp_close(&dzp))
	{
		logp("Error closing %s in %s\n", dst, __func__);
		goto end;
	}

	ret=0;
end:
	fzp_close(&azp);
	fzp_close(&bzp);
	fzp_close(&dzp);
	sbuf_free(&asb);
	sbuf_free(&bsb);
	hooks_free(&anew);
	hooks_free(&bnew);
	free_v((void **)&afingerprints);
	free_v((void **)&bfingerprints);
	free_w(&apath);
	free_w(&bpath);
	return ret;
}

#ifndef UTEST
static
#endif
int dindex_gzprintf(struct fzp *fzp, uint64_t *dindex)
{
	struct blk blk;
	struct iobuf wbuf;
	blk.savepath=*dindex;
	blk_to_iobuf_savepath(&blk, &wbuf);
	return iobuf_send_msg_fzp(&wbuf, fzp);
}

// Return 0 for OK, -1 for error, 1 for finished reading the file.
static int get_next_dindex(uint64_t **dnew, struct sbuf *sb, struct fzp *fzp)
{
	static struct blk blk;
	static struct iobuf rbuf;

	memset(&rbuf, 0, sizeof(rbuf));

	switch(iobuf_fill_from_fzp(&rbuf, fzp))
	{
		case -1: goto error;
		case 1: return 1; // Reached the end.
	}
	if(rbuf.cmd==CMD_SAVE_PATH)
	{
		if(blk_set_from_iobuf_savepath(&blk, &rbuf))
			goto error;
		*dnew=(uint64_t *)malloc_w(sizeof(uint64_t), __func__);
		**dnew=blk.savepath;
		iobuf_free_content(&rbuf);
		return 0;
	}
	else
		iobuf_log_unexpected(&sb->path, __func__);

error:
	iobuf_free_content(&rbuf);
	return -1;
}

/* Merge two files of sorted dindexes into each other. */
int merge_dindexes(const char *dst, const char *srca, const char *srcb)
{
	int ret=-1;
	struct sbuf *asb=NULL;
	struct sbuf *bsb=NULL;
	struct fzp *azp=NULL;
	struct fzp *bzp=NULL;
	struct fzp *dzp=NULL;
	uint64_t *anew=NULL;
	uint64_t *bnew=NULL;

	if(!(asb=sbuf_alloc(PROTO_2))
	  || (srcb && !(bsb=sbuf_alloc(PROTO_2))))
		goto end;
	if(build_path_w(dst))
		goto end;
	if((srca && !(azp=fzp_gzopen(srca, "rb")))
	  || (srcb && !(bzp=fzp_gzopen(srcb, "rb")))
	  || !(dzp=fzp_gzopen(dst, "wb")))
		goto end;

	while(azp || bzp || anew || bnew)
	{
		if(azp
		  && asb
		  && !anew)
		{
			switch(get_next_dindex(&anew, asb, azp))
			{
				case -1: goto end;
				case 1: fzp_close(&azp); // Finished OK.
			}
		}

		if(bzp
		  && bsb
		  && !bnew)
		{
			switch(get_next_dindex(&bnew, bsb, bzp))
			{
				case -1: goto end;
				case 1: fzp_close(&bzp); // Finished OK.
			}
		}

		if(anew && !bnew)
		{
			if(dindex_gzprintf(dzp, anew)) goto end;
			free_v((void **)&anew);
		}
		else if(!anew && bnew)
		{
			if(dindex_gzprintf(dzp, bnew)) goto end;
			free_v((void **)&bnew);
		}
		else if(!anew && !bnew)
		{
			continue;
		}
		else if(*anew==*bnew)
		{
			// They were the same - write the new one.
			if(dindex_gzprintf(dzp, bnew)) goto end;
			free_v((void **)&anew);
			free_v((void **)&bnew);
		}
		else if(*anew<*bnew)
		{
			if(dindex_gzprintf(dzp, anew)) goto end;
			free_v((void **)&anew);
		}
		else
		{
			if(dindex_gzprintf(dzp, bnew)) goto end;
			free_v((void **)&bnew);
		}
	}

	if(fzp_close(&dzp))
	{
		logp("Error closing %s in %s\n", dst, __func__);
		goto end;
	}

	ret=0;
end:
	fzp_close(&azp);
	fzp_close(&bzp);
	fzp_close(&dzp);
	sbuf_free(&asb);
	sbuf_free(&bsb);
	free_v((void **)&anew);
	free_v((void **)&bnew);
	return ret;
}

static char *get_global_sparse_tmp(const char *global)
{
	return prepend_n(global, "tmp", strlen("tmp"), ".");
}

int merge_into_global_sparse(
	const char *sparse,
	const char *global_sparse,
	struct lock *lock
) {
	int ret=-1;
	struct stat statp;
	char *tmpfile=NULL;
	const char *globalsrc=NULL;

	if(lock->status!=GET_LOCK_GOT)
	{
		logp("Attempt to merge into sparse index without a lock!\n");
		goto end;
	}

	if(!(tmpfile=get_global_sparse_tmp(global_sparse)))
		goto end;

	if(!lstat(global_sparse, &statp)) globalsrc=global_sparse;

	if(merge_sparse_indexes(tmpfile, globalsrc, sparse))
		goto end;

	// FIX THIS: nasty race condition needs to be recoverable.
	if(do_rename(tmpfile, global_sparse))
		goto end;

	ret=0;
end:
	free_w(&tmpfile);
	return ret;
}

static int lock_and_merge_into_global_sparse(
	const char *sparse,
	const char *global_sparse,
	struct conf **conf,
	struct sdirs *sdirs
) {
	int ret=-1;
	struct lock *lock=NULL;
	struct cstat *clist=NULL;
	
	if(!(lock=try_to_get_sparse_lock(global_sparse)))
		goto end;

	if(merge_into_global_sparse(sparse, global_sparse, lock))
		goto end;

	if(get_client_list(&clist, sdirs->clients, conf))
		goto end;

	if(sparse_minimise(conf, sdirs->global_sparse, lock, clist))
		goto end;

	ret=0;
end:
	lock_release(lock);
	lock_free(&lock);
	clist_free(&clist);
	return ret;
}

int merge_files_in_dir(const char *final, const char *fmanifest,
	const char *srcdir, uint64_t fcount,
	int merge(const char *dst, const char *srca, const char *srcb))
{
	int ret=-1;
	uint64_t i=0;
	uint64_t pass=0;
	char *m1dir=NULL;
	char *m2dir=NULL;
	char *srca=NULL;
	char *srcb=NULL;
	char *dst=NULL;
	char compa[32]="";
	char compb[32]="";
	char compd[32]="";
	char *fullsrcdir=NULL;

	if(!(m1dir=prepend_s(fmanifest, "m1"))
	  || !(m2dir=prepend_s(fmanifest, "m2"))
	  || !(fullsrcdir=prepend_s(fmanifest, srcdir)))
		goto end;
	if(recursive_delete(m1dir)
	  || recursive_delete(m2dir))
		goto end;
	while(1)
	{
		const char *srcdir=NULL;
		const char *dstdir=NULL;
		if(!pass)
		{
			srcdir=fullsrcdir;
			dstdir=m1dir;
		}
		else if(pass%2)
		{
			srcdir=m1dir;
			dstdir=m2dir;
		}
		else
		{
			srcdir=m2dir;
			dstdir=m1dir;
		}
		pass++;
		for(i=0; i<fcount; i+=2)
		{
			free_w(&srca);
			free_w(&srcb);
			free_w(&dst);
			snprintf(compa, sizeof(compa), "%08" PRIX64, i);
			snprintf(compb, sizeof(compb), "%08" PRIX64, i+1);
			snprintf(compd, sizeof(compd), "%08" PRIX64, i/2);
			if(!(srca=prepend_s(srcdir, compa))
			  || !(dst=prepend_s(dstdir, compd)))
				goto end;
			if(i+1<fcount
			  && !(srcb=prepend_s(srcdir, compb)))
				goto end;
			if(merge(dst, srca, srcb))
				goto end;
		}
		fcount=i/2;
		if(fcount<2) break;
	}

	// FIX THIS: nasty race condition here needs to be automatically
	// recoverable.
	if(dst && do_rename(dst, final))
		goto end;
	if(recursive_delete(m1dir)
	  || recursive_delete(m2dir))
		goto end;

	ret=0;
end:
	free_w(&m1dir);
	free_w(&m2dir);
	free_w(&srca);
	free_w(&srcb);
	free_w(&dst);
	free_w(&fullsrcdir);
	return ret;
}

int merge_files_in_dir_no_fcount(const char *final, const char *fmanifest,
	int merge(const char *dst, const char *srca, const char *srcb))
{
	int ret=-1;
	int n=0;
	int i=0;
	char *dst=NULL;
	char *dstdir=NULL;
	char compd[32]="";
	char *fullpath=NULL;
	uint64_t fcount=0;
	struct dirent **dir=NULL;
	struct strlist *s=NULL;
	struct strlist *slist=NULL;

	if(!(dstdir=prepend_s(fmanifest, "n1")))
		goto end;
	if(recursive_delete(dstdir))
		goto end;

	// Files are unsorted, and not named sequentially.
	if((n=scandir(fmanifest, &dir, filter_dot, NULL))<0)
	{
		logp("scandir failed for %s in %s: %s\n",
			fmanifest, __func__, strerror(errno));
		goto end;
	}
	for(i=0; i<n; i++)
	{
		free_w(&fullpath);
		if(!(fullpath=prepend_s(fmanifest, dir[i]->d_name)))
			goto end;
		switch(is_dir(fullpath, dir[i]))
		{
			case 0: break;
			case 1: continue;
			default: logp("is_dir(%s): %s\n",
					fullpath, strerror(errno));
				goto end;
		}

		// Have a good entry. Add it to the list.
		if(strlist_add(&slist, fullpath, 0))
			goto end;
		fcount++;
	}

	// Merge them all into a directory, name the files sequentially.
	i=0;
	for(s=slist; s; s=s->next)
	{
		free_w(&dst);
		snprintf(compd, sizeof(compd), "%08" PRIX64, (uint64_t)i++);
		if(!(dst=prepend_s(dstdir, compd)))
			goto end;
		if(merge(dst, s->path, s->next?s->next->path:NULL))
			goto end;
	}

	// Now do a normal merge.
	if(merge_files_in_dir(final, fmanifest, "n1", fcount, merge))
		goto end;

	ret=0;
end:
	recursive_delete(dstdir);
	strlists_free(&slist);
	free_w(&dstdir);
	free_w(&dst);
	free_w(&fullpath);
	if(dir)
	{
		for(i=0; i<n; i++)
			free(dir[i]);
		free(dir);
	}
	return ret;
}

int backup_phase4_server_protocol2(struct sdirs *sdirs, struct conf **confs)
{
	int ret=-1;
	char *dfiles=NULL;
	char *sparse=NULL;
	struct manio *newmanio=NULL;
	char *logpath=NULL;
	char *fmanifest=NULL; // FIX THIS: should be part of sdirs.

	if(!(logpath=prepend_s(sdirs->finishing, "log")))
		goto end;
	if(log_fzp_set(logpath, confs))
		goto end;

	logp("Begin phase4 (sparse generation)\n");

	if(!(fmanifest=prepend_s(sdirs->finishing, "manifest"))
	  || !(newmanio=manio_open(fmanifest, "rb", PROTO_2))
	  || manio_read_fcount(newmanio)
	  || !(dfiles=prepend_s(fmanifest, "dfiles"))
	  || !(sparse=prepend_s(fmanifest, "sparse")))
		goto end;

	if(merge_files_in_dir(dfiles, fmanifest, "dindex",
		newmanio->offset->fcount,
		merge_dindexes))
			goto end;
	if(merge_files_in_dir(sparse, fmanifest, "hooks",
		newmanio->offset->fcount,
		merge_sparse_indexes))
			goto end;

	if(lock_and_merge_into_global_sparse(sparse,
		sdirs->global_sparse, confs, sdirs))
			goto end;

	logp("End phase4 (sparse generation)\n");

	ret=0;
end:
	manio_close(&newmanio);
	free_w(&sparse);
	free_w(&logpath);
	free_w(&fmanifest);
	return ret;
}

static void wait_for_champ_dindex_lock(struct sdirs *sdirs)
{
	while(lock_test(sdirs->champ_dindex_lock))
	{
		logp("Waiting for %s\n", sdirs->champ_dindex_lock);
		sleep(3);
	}
}

// Never call this outside of backup phases 2 to 4, because it cannot run
// at the same time as the champ chooser starts up - that is when the champ
// chooser attempts to delete data files. If the champ chooser attempts to
// delete data files whilst the dindex is being regenerated, data could be
// lost.
// Backup phase 2 may start a champ chooser, and the champ chooser will not
// attempt deletion if any client in the dedup_group has working/finishing
// symlinks or a dfiles.regenerating file.
int regenerate_client_dindex(struct sdirs *sdirs)
{
	int ret=-1;
	struct bu *bu;
	struct bu *bu_list=NULL;
	char *newpath=NULL;
	char *oldpath=NULL;
	char tmp[16]="";
	int path_built=0;
	uint64_t last_index=0;
	char *dfiles_new=NULL;
	char *dfiles_regenerating=NULL;
	struct fzp *fzp=NULL;

	if(bu_get_list_with_working(sdirs, &bu_list))
		goto end;

	for(bu=bu_list; bu; bu=bu->next)
	{
		snprintf(tmp, sizeof(tmp), "%08" PRIX64, bu->index-1);
		if(!(newpath=prepend_s(sdirs->dindex, tmp))
		  || !(oldpath=prepend_s(bu->path, "manifest/dfiles")))
			goto end;
		if(!path_built)
		{
			if(build_path_w(newpath))
				goto end;
			path_built++;
		}
		if(link(oldpath, newpath))
		{
			logp("%s could not hard link '%s' to '%s': %s\n",
				__func__, oldpath, newpath, strerror(errno));
			goto end;
		}
		free_w(&newpath);
		free_w(&oldpath);
		last_index=(uint64_t)bu->index;
	}

	if(!(dfiles_new=prepend(sdirs->dfiles, ".new"))
	  || !(dfiles_regenerating=prepend(sdirs->dfiles, ".regenerating")))
		goto end;

	// dfiles.regenerating is checked in champ_chooser/dindex.c, the
	// champ chooser will not delete data files if it exists. We need
	// to make sure the champ chooser does not try to delete data files
	// whilst we have dfiles in an inconsistent state, or data will be
	// lost.
	// If we are interrupted after this point, the champ chooser deletion
	// code will not run again until this code here is re-run (or somebody
	// deletes dfiles_regenerating by hand, which they should not do).
	if(!(fzp=fzp_open(dfiles_regenerating, "wb"))
	  || fzp_close(&fzp))
		goto end;

	if(recursive_delete(dfiles_new))
		goto end;
	if(merge_files_in_dir(dfiles_new, sdirs->client,
		"dindex", last_index, merge_dindexes))
			goto end;

	// If the champ chooser is deleting files, we do not want to mess with
	// our dindex/dfiles. Wait until it is finished.
	wait_for_champ_dindex_lock(sdirs);

	if(recursive_delete(sdirs->dindex))
		goto end;
	if(do_rename(dfiles_new, sdirs->dfiles))
		goto end;
	if(recursive_delete(sdirs->dindex))
		goto end;

	if(unlink_w(dfiles_regenerating, __func__))
		goto end;

	ret=0;
end:
	bu_list_free(&bu_list);
	free_w(&dfiles_new);
	free_w(&dfiles_regenerating);
	free_w(&newpath);
	free_w(&oldpath);
	return ret;
}

int remove_backup_from_global_sparse(const char *global_sparse,
	const char *candidate_str)
{
	int ret=-1;
	struct lock *lock=NULL;
	struct sbuf *asb=NULL;
	uint64_t *afingerprints=NULL;
	size_t aflen=0;
	size_t clen=0;
	struct fzp *azp=NULL;
	struct fzp *dzp=NULL;
	struct hooks *anew=NULL;
	char *apath=NULL;
	char *tmpfile=NULL;

	logp("Removing %s from %s\n", candidate_str, global_sparse);
	if(!(lock=try_to_get_sparse_lock(global_sparse)))
		goto end;

	if(!(tmpfile=get_global_sparse_tmp(global_sparse))
	  || !(azp=fzp_gzopen(global_sparse, "rb"))
	  || !(dzp=fzp_gzopen(tmpfile, "wb"))
	  || !(asb=sbuf_alloc(PROTO_2)))
		goto end;

	clen=strlen(candidate_str);

	while(azp)
	{
		switch(get_next_set_of_hooks(&anew, asb, azp,
			&apath, &afingerprints, &aflen))
		{
			case -1: goto end;
			case 1: fzp_close(&azp); // Finished OK.
		}

		if(!anew) continue;

		if(!strncmp(anew->path, candidate_str, clen)
		  && *(anew->path+clen)=='/')
			continue;

		if(hooks_gzprintf(dzp, anew)) goto end;
		hooks_free(&anew);
	}

	if(fzp_close(&dzp))
	{
		logp("Error closing %s in %s\n", tmpfile, __func__);
		goto end;
	}

	// FIX THIS: nasty race condition needs to be recoverable.
	if(do_rename(tmpfile, global_sparse))
		goto end;

	ret=0;
end:
	fzp_close(&azp);
	fzp_close(&dzp);
	lock_release(lock);
	lock_free(&lock);
	sbuf_free(&asb);
	hooks_free(&anew);
	free_v((void **)&afingerprints);
	free_w(&apath);
	free_w(&tmpfile);
	return ret;
}
