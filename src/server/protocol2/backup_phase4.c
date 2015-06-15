#include "include.h"
#include "../../cmd.h"
#include "../../lock.h"
#include "../../server/manio.h"
#include "../../server/sdirs.h"

#define WEAK_LEN	16
#define WEAK_STR_LEN	WEAK_LEN+1

struct hooks
{
	char *path;
	char *fingerprints;
};

static int hookscmp(const struct hooks **a, const struct hooks **b)
{
	return strcmp((*a)->fingerprints, (*b)->fingerprints);
}

static int hooks_alloc(struct hooks **hnew, char **path, char **fingerprints)
{
	if(!*path || !*fingerprints) return 0;

	if(!(*hnew=(struct hooks *)malloc_w(sizeof(struct hooks), __func__)))
		return -1;
	
	(*hnew)->path=*path;
	(*hnew)->fingerprints=*fingerprints;
	*fingerprints=NULL;
	*path=NULL;
	return 0;
}

// Return 0 for OK, -1 for error, 1 for finished reading the file.
static int get_next_set_of_hooks(struct hooks **hnew, struct sbuf *sb,
	struct fzp *spzp, char **path, char **fingerprints,
	struct conf **confs)
{
	while(1)
	{
		switch(sbuf_fill(sb, NULL /* struct async */,
			spzp, NULL, NULL, confs))
		{
			case -1: goto error;
			case 1:
				// Reached the end.
				if(hooks_alloc(hnew, path, fingerprints))
					goto error;
				return 1;
		}
		if(sb->path.cmd==CMD_MANIFEST)
		{
			if(hooks_alloc(hnew, path, fingerprints))
				break;
			free_w(fingerprints);
			free_w(path);
			*path=sb->path.buf;
			sb->path.buf=NULL;
			sbuf_free_content(sb);
			if(*hnew) return 0;
		}
		else if(sb->path.cmd==CMD_FINGERPRINT)
		{
			if(astrcat(fingerprints, sb->path.buf, __func__))
				break;
			sbuf_free_content(sb);
		}
		else
		{
			iobuf_log_unexpected(&sb->path, __func__);
			break;
		}
	}

error:
	return -1;
}

static int gzprintf_hooks(struct fzp *fzp, struct hooks *hooks)
{
	static char *f;
	static char ftmp[WEAK_STR_LEN];
	size_t len=strlen(hooks->fingerprints);

//	printf("NW: %c%04lX%s\n", CMD_MANIFEST,
//		strlen(hooks->path), hooks->path);
	fzp_printf(fzp, "%c%04lX%s\n", CMD_MANIFEST,
		strlen(hooks->path), hooks->path);
	for(f=hooks->fingerprints; f<hooks->fingerprints+len; f+=WEAK_LEN)
	{
		snprintf(ftmp, sizeof(ftmp), "%s", f);
		fzp_printf(fzp, "%c%04lX%s\n", CMD_FINGERPRINT,
			strlen(ftmp), ftmp);
	}
	return 0;
}

static void hooks_free(struct hooks **hooks)
{
	if(!*hooks) return;
	free_w(&(*hooks)->path);
	free_w(&(*hooks)->fingerprints);
	free_v((void **)hooks);
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

/* Merge two files of sorted sparse indexes into each other. */
static int merge_sparse_indexes(const char *srca, const char *srcb,
	const char *dst, struct conf **confs)
{
	int fcmp;
	int ret=-1;
	struct sbuf *asb=NULL;
	struct sbuf *bsb=NULL;
	char *afingerprints=NULL;
	char *bfingerprints=NULL;
	struct fzp *azp=NULL;
	struct fzp *bzp=NULL;
	struct fzp *dzp=NULL;
	struct hooks *anew=NULL;
	struct hooks *bnew=NULL;
	char *apath=NULL;
	char *bpath=NULL;

	if(!(asb=sbuf_alloc(confs))
	  || (srcb && !(bsb=sbuf_alloc(confs))))
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
				&apath, &afingerprints, confs))
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
				&bpath, &bfingerprints, confs))
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
		else if(!(fcmp=hookscmp(
		  (const struct hooks **)&anew,
		  (const struct hooks **)&bnew)))
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
	if(afingerprints) free(afingerprints);
	if(bfingerprints) free(bfingerprints);
	if(apath) free(apath);
	if(bpath) free(bpath);
	return ret;
}

static int merge_into_global_sparse(const char *sparse, const char *global,
	struct conf **confs)
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

	if(merge_sparse_indexes(sparse, globalsrc, tmpfile, confs))
		goto end;

	// FIX THIS: nasty race condition needs to be recoverable.
	if(do_rename(tmpfile, global)) goto end;

	ret=0;
end:
	lock_release(lock);
	lock_free(&lock);
	if(lockfile) free(lockfile);
	if(tmpfile) free(tmpfile);
	return ret;
}

int backup_phase4_server_protocol2(struct sdirs *sdirs, struct conf **confs)
{
	int ret=-1;
	uint64_t i=0;
	uint64_t pass=0;
	char *sparse=NULL;
	char *global_sparse=NULL;
	char *h1dir=NULL;
	char *h2dir=NULL;
	char *hooksdir=NULL;
	char *srca=NULL;
	char *srcb=NULL;
	char *dst=NULL;
	char compa[32]="";
	char compb[32]="";
	char compd[32]="";
	struct manio *newmanio=NULL;
	char *logpath=NULL;
	char *fmanifest=NULL; // FIX THIS: should be part of sdirs.

	if(!(logpath=prepend_s(sdirs->finishing, "log")))
		goto end;
	if(set_logfzp(logpath, confs))
		goto end;

	logp("Begin phase4 (sparse generation)\n");

	if(!(fmanifest=prepend_s(sdirs->finishing, "manifest"))
	  || !(newmanio=manio_open(fmanifest, "rb", PROTO_2))
	  || manio_read_fcount(newmanio)
	  || !(hooksdir=prepend_s(fmanifest, "hooks"))
	  || !(h1dir=prepend_s(fmanifest, "h1"))
	  || !(h2dir=prepend_s(fmanifest, "h2")))
		goto end;

	while(1)
	{
		char *srcdir=NULL;
		char *dstdir=NULL;
		if(!pass)
		{
			srcdir=hooksdir;
			dstdir=h1dir;
		}
		else if(pass%2)
		{
			srcdir=h1dir;
			dstdir=h2dir;
		}
		else
		{
			srcdir=h2dir;
			dstdir=h1dir;
		}
		pass++;
		for(i=0; i<newmanio->offset->fcount; i+=2)
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
			if(i+1<newmanio->offset->fcount
			  && !(srcb=prepend_s(srcdir, compb)))
				goto end;
			if(merge_sparse_indexes(srca, srcb, dst, confs))
				goto end;
		}
		if((newmanio->offset->fcount=i/2)<2) break;
	}

	if(!(sparse=prepend_s(fmanifest, "sparse"))
	  || !(global_sparse=prepend_s(sdirs->data, "sparse")))
		goto end;

	// FIX THIS: nasty race condition here needs to be automatically
	// recoverable.
	if(do_rename(dst, sparse)) goto end;

	if(merge_into_global_sparse(sparse, global_sparse, confs)) goto end;

	logp("End phase4 (sparse generation)\n");

	ret=0;
end:
	manio_close(&newmanio);
	free_w(&sparse);
	free_w(&global_sparse);
	free_w(&srca);
	free_w(&srcb);
	recursive_delete(h1dir);
	recursive_delete(h2dir);
	free_w(&h1dir);
	free_w(&h2dir);
	free_w(&logpath);
	free_w(&fmanifest);
	return ret;
}
