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
	gzFile spzp, char **path, char **fingerprints,
	struct conf **confs)
{
	while(1)
	{
		switch(sbuf_fill_from_gzfile(sb,
			NULL /* struct async */,
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

static int gzprintf_hooks(gzFile tzp, struct hooks *hooks)
{
	static char *f;
	static char ftmp[WEAK_STR_LEN];
	size_t len=strlen(hooks->fingerprints);

//	printf("NW: %c%04lX%s\n", CMD_MANIFEST,
//		strlen(hooks->path), hooks->path);
	gzprintf(tzp, "%c%04lX%s\n", CMD_MANIFEST,
		strlen(hooks->path), hooks->path);
	for(f=hooks->fingerprints; f<hooks->fingerprints+len; f+=WEAK_LEN)
	{
		snprintf(ftmp, sizeof(ftmp), "%s", f);
		gzprintf(tzp, "%c%04lX%s\n", CMD_FINGERPRINT,
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
	gzFile azp=NULL;
	gzFile bzp=NULL;
	gzFile dzp=NULL;
	struct hooks *anew=NULL;
	struct hooks *bnew=NULL;
	char *apath=NULL;
	char *bpath=NULL;

	if(!(asb=sbuf_alloc(confs))
	  || (srcb && !(bsb=sbuf_alloc(confs))))
		goto end;
	if(build_path_w(dst))
		goto end;
	if(!(azp=gzopen_file(srca, "rb"))
	  || (srcb && !(bzp=gzopen_file(srcb, "rb")))
	  || !(dzp=gzopen_file(dst, "wb")))
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
				case 1: gzclose_fp(&azp); // Finished OK.
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
				case 1: gzclose_fp(&bzp); // Finished OK.
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

	if(gzclose_fp(&dzp))
	{
		logp("Error closing %s in %s\n", tmpfile, __func__);
		goto end;
	}

	ret=0;
end:
	gzclose_fp(&azp);
	gzclose_fp(&bzp);
	gzclose_fp(&dzp);
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
	
	if(!(tmpfile=prepend(global, "tmp", strlen("tmp"), ".")))
		goto end;

	// Get a lock before messing with the global sparse index.
	if(!(lockfile=prepend(global, "lock", strlen("lock"), "."))
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

int sparse_generation(struct manio *newmanio, uint64_t fcount,
	struct sdirs *sdirs, struct conf **confs)
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

	if(!(hooksdir=prepend_s(sdirs->rmanifest, "hooks"))
	  || !(h1dir=prepend_s(sdirs->rmanifest, "h1"))
	  || !(h2dir=prepend_s(sdirs->rmanifest, "h2")))
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
			if(i+1<fcount && !(srcb=prepend_s(srcdir, compb)))
				goto end;
			if(merge_sparse_indexes(srca, srcb, dst, confs))
				goto end;
		}
		if((fcount=i/2)<2) break;
	}

	if(!(sparse=prepend_s(sdirs->rmanifest, "sparse"))
	  || !(global_sparse=prepend_s(sdirs->data, "sparse")))
		goto end;

	// FIX THIS: nasty race condition here needs to be automatically
	// recoverable.
	if(do_rename(dst, sparse)) goto end;

	if(merge_into_global_sparse(sparse, global_sparse, confs)) goto end;

	ret=0;
end:
	free_w(&sparse);
	free_w(&global_sparse);
	free_w(&srca);
	free_w(&srcb);
	recursive_delete(h1dir, NULL, 1);
	recursive_delete(h2dir, NULL, 1);
	free_w(&h1dir);
	free_w(&h2dir);
	return ret;
}
