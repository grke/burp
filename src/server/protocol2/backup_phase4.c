#include "include.h"
#include "../../cmd.h"
#include "../../lock.h"
#include "../../protocol2/blk.h"
#include "../../server/manio.h"
#include "../../server/sdirs.h"

struct hooks
{
	char *path;
	uint64_t *fingerprints;
	size_t len;
};

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
static int get_next_set_of_hooks(struct hooks **hnew, struct sbuf *sb,
	struct fzp *spzp, char **path, uint64_t **fingerprints, size_t *len)
{
	struct blk blk;
	while(1)
	{
		switch(sbuf_fill_from_file(sb, spzp, NULL, NULL))
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

static int gzprintf_hooks(struct fzp *fzp, struct hooks *hooks)
{
	size_t i;
	fzp_printf(fzp, "%c%04lX%s\n", CMD_MANIFEST,
		strlen(hooks->path), hooks->path);
	for(i=0; i<hooks->len; i++)
		if(to_fzp_fingerprint(fzp, hooks->fingerprints[i]))
			return -1;
	return 0;
}

static void hooks_free(struct hooks **hooks)
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
	if(!(azp=fzp_gzopen(srca, "rb"))
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
			if(gzprintf_hooks(dzp, anew)) goto end;
			hooks_free(&anew);
		}
		else if(!anew && bnew)
		{
			if(gzprintf_hooks(dzp, bnew)) goto end;
			hooks_free(&bnew);
		}
		else if(!anew && !bnew)
		{
			continue;
		}
		else if(!(fcmp=hookscmp(anew, bnew)))
		{
			// They were the same - write the new one.
			if(gzprintf_hooks(dzp, bnew)) goto end;
			hooks_free(&anew);
			hooks_free(&bnew);
		}
		else if(fcmp<0)
		{
			if(gzprintf_hooks(dzp, anew)) goto end;
			hooks_free(&anew);
		}
		else
		{
			if(gzprintf_hooks(dzp, bnew)) goto end;
			hooks_free(&bnew);
		}
	}

	if(fzp_close(&dzp))
	{
		logp("Error closing %s in %s\n", tmpfile, __func__);
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
int gzprintf_dindex(struct fzp *fzp, uint64_t *dindex)
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
#ifndef UTEST
static
#endif
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
	if(!(azp=fzp_gzopen(srca, "rb"))
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
			if(gzprintf_dindex(dzp, anew)) goto end;
			free_v((void **)&anew);
		}
		else if(!anew && bnew)
		{
			if(gzprintf_dindex(dzp, bnew)) goto end;
			free_v((void **)&bnew);
		}
		else if(!anew && !bnew)
		{
			continue;
		}
		else if(*anew==*bnew)
		{
			// They were the same - write the new one.
			if(gzprintf_dindex(dzp, bnew)) goto end;
			free_v((void **)&anew);
			free_v((void **)&bnew);
		}
		else if(*anew<*bnew)
		{
			if(gzprintf_dindex(dzp, anew)) goto end;
			free_v((void **)&anew);
		}
		else
		{
			if(gzprintf_dindex(dzp, bnew)) goto end;
			free_v((void **)&bnew);
		}
	}

	if(fzp_close(&dzp))
	{
		logp("Error closing %s in %s\n", tmpfile, __func__);
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

static void try_lock_msg(int seconds)
{
	logp("Unable to get sparse lock for %d seconds.\n", seconds);
}

static int try_to_get_lock(struct lock *lock)
{
	// Sleeping for 1800*2 seconds makes 1 hour.
	// This should be super generous.
	int lock_tries=0;
	int lock_tries_max=1800;
	int sleeptime=2;

	while(1)
	{
		lock_get(lock);
		switch(lock->status)
		{
			case GET_LOCK_GOT:
				logp("Got sparse lock\n");
				return 0;
			case GET_LOCK_NOT_GOT:
				lock_tries++;
				if(lock_tries>lock_tries_max)
				{
					try_lock_msg(lock_tries_max*sleeptime);
					return -1;
				}
				// Log every 10 seconds.
				if(lock_tries%(10/sleeptime))
				{
					try_lock_msg(lock_tries_max*sleeptime);
					logp("Giving up.\n");
					return -1;
				}
				sleep(sleeptime);
				continue;
			case GET_LOCK_ERROR:
			default:
				logp("Unable to get global sparse lock.\n");
				return -1;
		}
	}
	// Never reached.
	return -1;
}

static int merge_into_global_sparse(const char *sparse, const char *global)
{
	int ret=-1;
	char *tmpfile=NULL;
	struct stat statp;
	char *lockfile=NULL;
	struct lock *lock=NULL;
	const char *globalsrc=NULL;
	
	if(!(tmpfile=prepend_n(global, "tmp", strlen("tmp"), ".")))
		goto end;

	// Get a lock before messing with the global sparse index.
	if(!(lockfile=prepend_n(global, "lock", strlen("lock"), "."))
	  || !(lock=lock_alloc_and_init(lockfile)))
		goto end;

	if(try_to_get_lock(lock)) goto end;

	if(!lstat(global, &statp)) globalsrc=global;

	if(merge_sparse_indexes(tmpfile, sparse, globalsrc))
		goto end;

	// FIX THIS: nasty race condition needs to be recoverable.
	if(do_rename(tmpfile, global)) goto end;

	ret=0;
end:
	lock_release(lock);
	lock_free(&lock);
	free_w(&lockfile);
	free_w(&tmpfile);
	return ret;
}

static int merge_into_client_dindex(const char *dfiles,
	const char *client_dfiles)
{
	int ret=-1;
	char *tmpfile=NULL;
	struct stat statp;
	const char *client_src=NULL;

	// Rely on the current process having already got a lock for this
	// client, so do not do any locking for now.
	
	if(!(tmpfile=prepend_n(client_dfiles, "tmp", strlen("tmp"), ".")))
		goto end;

	if(!lstat(client_dfiles, &statp)) client_src=client_dfiles;

	if(merge_dindexes(tmpfile, dfiles, client_src))
		goto end;

	// FIX THIS: nasty race condition needs to be recoverable.
	if(do_rename(tmpfile, client_dfiles)) goto end;

	ret=0;
end:
	free_w(&tmpfile);
	return ret;
}

#ifndef UTEST
static
#endif
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
			snprintf(compa, sizeof(compa), "%08"PRIX64, i);
			snprintf(compb, sizeof(compb), "%08"PRIX64, i+1);
			snprintf(compd, sizeof(compd), "%08"PRIX64, i/2);
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
	// The rename will give an error on fcount==0, which is OK because
	// fcount will always be at least 1.
	if(do_rename(dst, final)
	  || recursive_delete(m1dir)
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

int backup_phase4_server_protocol2(struct sdirs *sdirs, struct conf **confs)
{
	int ret=-1;
	char *dfiles=NULL;
	char *sparse=NULL;
	char *global_sparse=NULL;
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

	if(!(global_sparse=prepend_s(sdirs->data, "sparse"))
	  || merge_into_global_sparse(sparse, global_sparse)
	  || merge_into_client_dindex(dfiles, sdirs->dfiles)) goto end;

	logp("End phase4 (sparse generation)\n");

	ret=0;
end:
	manio_close(&newmanio);
	free_w(&sparse);
	free_w(&global_sparse);
	free_w(&logpath);
	free_w(&fmanifest);
	return ret;
}
