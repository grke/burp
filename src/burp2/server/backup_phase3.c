#include "include.h"

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

	if(!(*hnew=(struct hooks *)malloc(sizeof(struct hooks))))
	{
		log_out_of_memory(__FUNCTION__);
		return -1;
	}
	
	(*hnew)->path=*path;
	(*hnew)->fingerprints=*fingerprints;
	*fingerprints=NULL;
	*path=NULL;
	return 0;
}

// Return 0 for OK, -1 for error, 1 for finished reading the file.
static int get_next_set_of_hooks(struct hooks **hnew, struct sbuf *sb,
	gzFile spzp, char **path, char **fingerprints,
	struct conf *conf)
{
	while(1)
	{
		switch(sbuf_fill_from_gzfile(sb,
			NULL /* struct async */,
			spzp, NULL, NULL, conf))
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
			if(*fingerprints)
			{
				free(*fingerprints);
				*fingerprints=NULL;
			}
			if(*path) free(*path);
			*path=sb->path.buf;
			sb->path.buf=NULL;
			sbuf_free_content(sb);
			if(*hnew) return 0;
		}
		else if(sb->path.cmd==CMD_FINGERPRINT)
		{
			if(astrcat(fingerprints, sb->path.buf))
				break;
			sbuf_free_content(sb);
		}
		else
		{
			iobuf_log_unexpected(&sb->path, __FUNCTION__);
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
	if((*hooks)->path) free((*hooks)->path);
	if((*hooks)->fingerprints) free((*hooks)->fingerprints);
	free(*hooks);
	*hooks=NULL;
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
	const char *dst, struct conf *conf)
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

	if(!(asb=sbuf_alloc(conf))
	  || (srcb && !(bsb=sbuf_alloc(conf))))
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
				&apath, &afingerprints, conf))
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
				&bpath, &bfingerprints, conf))
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
		logp("Error closing %s in %s\n", tmpfile, __FUNCTION__);
		goto end;
	}

	ret=0;
end:
	gzclose_fp(&azp);
	gzclose_fp(&bzp);
	gzclose_fp(&dzp);
	sbuf_free(asb);
	sbuf_free(bsb);
	hooks_free(&anew);
	hooks_free(&bnew);
	if(afingerprints) free(afingerprints);
	if(bfingerprints) free(bfingerprints);
	if(apath) free(apath);
	if(bpath) free(bpath);
	return ret;
}

static int merge_into_global_sparse(const char *sparse, const char *global,
	struct conf *conf)
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

	if(merge_sparse_indexes(sparse, globalsrc, tmpfile, conf))
		goto end;

	if(do_rename(tmpfile, global)) goto end;

	ret=0;
end:
	lock_release(lock);
	lock_free(&lock);
	if(lockfile) free(lockfile);
	if(tmpfile) free(tmpfile);
	return ret;
}

static int sparse_generation(struct manio *newmanio, uint64_t fcount,
	const char *datadir, const char *manifest_dir, struct conf *conf)
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

	if(!(hooksdir=prepend_s(manifest_dir, "hooks"))
	  || !(h1dir=prepend_s(manifest_dir, "h1"))
	  || !(h2dir=prepend_s(manifest_dir, "h2")))
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
			if(srca) { free(srca); srca=NULL; }
			if(srcb) { free(srcb); srcb=NULL; }
			if(dst) { free(dst); dst=NULL; }
			snprintf(compa, sizeof(compa), "%08lX", i);
			snprintf(compb, sizeof(compb), "%08lX", i+1);
			snprintf(compd, sizeof(compd), "%08lX", i/2);
			if(!(srca=prepend_s(srcdir, compa))
			  || !(dst=prepend_s(dstdir, compd)))
				goto end;
			if(i+1<fcount && !(srcb=prepend_s(srcdir, compb)))
				goto end;
			if(merge_sparse_indexes(srca, srcb, dst, conf))
				goto end;
		}
		if((fcount=i/2)<2) break;
	}

	if(!(sparse=prepend_s(manifest_dir, "sparse"))
	  || !(global_sparse=prepend_s(datadir, "sparse")))
		goto end;

	if(do_rename(dst, sparse)) goto end;

	if(merge_into_global_sparse(sparse, global_sparse, conf)) goto end;

	ret=0;
end:
	if(sparse) free(sparse);
	if(global_sparse) free(global_sparse);
	if(srca) free(srca);
	if(srcb) free(srcb);
	recursive_delete(h1dir, NULL, 1);
	recursive_delete(h2dir, NULL, 1);
	if(h1dir) free(h1dir);
	if(h2dir) free(h2dir);
	return ret;
}

// This is basically backup_phase3_server() from burp1. It used to merge the
// unchanged and changed data into a single file. Now it splits the manifests
// into several files.
int backup_phase3_server(struct sdirs *sdirs,
	const char *manifest_dir, struct conf *conf)
{
	int ret=1;
	int pcmp=0;
	char *hooksdir=NULL;
	char *dindexdir=NULL;
	struct sbuf *usb=NULL;
	struct sbuf *csb=NULL;
	struct blk *blk=NULL;
	int finished_ch=0;
	int finished_un=0;
	struct manio *newmanio=NULL;
	struct manio *chmanio=NULL;
	struct manio *unmanio=NULL;
	uint64_t fcount=0;

	logp("Start phase3\n");

	if(!(newmanio=manio_alloc())
	  || !(chmanio=manio_alloc())
	  || !(unmanio=manio_alloc())
	  || !(hooksdir=prepend_s(manifest_dir, "hooks"))
	  || !(dindexdir=prepend_s(manifest_dir, "dindex"))
	  || manio_init_write(newmanio, manifest_dir)
	  || manio_init_write_hooks(newmanio, conf->directory, hooksdir)
	  || manio_init_write_dindex(newmanio, dindexdir)
	  || manio_init_read(chmanio, sdirs->changed)
	  || manio_init_read(unmanio, sdirs->unchanged)
	  || !(usb=sbuf_alloc(conf))
	  || !(csb=sbuf_alloc(conf)))
		goto end;

	while(!finished_ch || !finished_un)
	{
		if(!blk && !(blk=blk_alloc())) goto end;

		if(!finished_un
		  && usb
		  && !usb->path.buf)
		{
			switch(manio_sbuf_fill(unmanio, usb, NULL, NULL, conf))
			{
				case -1: goto end;
				case 1: finished_un++;
			}
		}

		if(!finished_ch
		  && csb
		  && !csb->path.buf)
		{
			switch(manio_sbuf_fill(chmanio, csb, NULL, NULL, conf))
			{
				case -1: goto end;
				case 1: finished_ch++;
			}
		}

		if((usb && usb->path.buf) && (!csb || !csb->path.buf))
		{
			switch(manio_copy_entry(&usb, usb,
				&blk, unmanio, newmanio, conf))
			{
				case -1: goto end;
				case 1: finished_un++;
			}
		}
		else if((!usb || !usb->path.buf) && (csb && csb->path.buf))
		{
			switch(manio_copy_entry(&csb, csb,
				&blk, chmanio, newmanio, conf))
			{
				case -1: goto end;
				case 1: finished_ch++;
			}
		}
		else if((!usb || !usb->path.buf) && (!csb || !(csb->path.buf)))
		{
			continue;
		}
		else if(!(pcmp=sbuf_pathcmp(usb, csb)))
		{
			// They were the same - write one.
			switch(manio_copy_entry(&csb, csb,
				&blk, chmanio, newmanio, conf))
			{
				case -1: goto end;
				case 1: finished_ch++;
			}
		}
		else if(pcmp<0)
		{
			switch(manio_copy_entry(&usb, usb,
				&blk, unmanio, newmanio, conf))
			{
				case -1: goto end;
				case 1: finished_un++;
			}
		}
		else
		{
			switch(manio_copy_entry(&csb, csb,
				&blk, chmanio, newmanio, conf))
			{
				case -1: goto end;
				case 1: finished_ch++;
			}
		}
	}

	fcount=newmanio->fcount;

	// Flush to disk and set up for reading.
	if(manio_free(newmanio)
	  || !(newmanio=manio_alloc())
	  || manio_init_read(newmanio, manifest_dir))
		goto end;

	if(sparse_generation(newmanio, fcount, sdirs->data, manifest_dir, conf))
		goto end;

	recursive_delete(chmanio->directory, NULL, 1);
	recursive_delete(unmanio->directory, NULL, 1);

	ret=0;

	logp("End phase3\n");
end:
	manio_free(newmanio);
	manio_free(chmanio);
	manio_free(unmanio);
	sbuf_free(csb);
	sbuf_free(usb);
	blk_free(blk);
	if(hooksdir) free(hooksdir);
	if(dindexdir) free(dindexdir);
	return ret;
}
