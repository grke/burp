#include "include.h"

static char sort_blk[SIG_MAX][16+1];
static int sort_ind=0;

static int write_header(gzFile spzp, const char *fpath, struct config *conf)
{
	const char *cp;
	cp=fpath+strlen(conf->directory);
	while(cp && *cp=='/') cp++;
	gzprintf(spzp, "%c%04X%s\n", CMD_MANIFEST, strlen(cp), cp);
	return 0;
}

static int write_hooks(gzFile spzp, const char *fpath, struct config *conf)
{
	int i=0;
	if(!sort_ind) return 0;
	if(write_header(spzp, fpath, conf)) return -1;
	qsort(sort_blk, sort_ind, 16+1,
		(int (*)(const void *, const void *))strcmp);
	for(i=0; i<sort_ind; i++)
	{
		// Do not bother with duplicates.
		if(i && !strcmp(sort_blk[i], sort_blk[i-1])) continue;
		gzprintf(spzp, "%c%04X%s\n", CMD_FINGERPRINT,
			strlen(sort_blk[i]), sort_blk[i]);
	}
	sort_ind=0;
	return 0;
}

static int copy_unchanged_entry(struct sbuf **csb, struct sbuf *sb, int *finished, struct blk **blk, struct manio *cmanio, struct manio *newmanio, const char *manifest_dir, struct config *conf)
{
	static int ars;
	static char *copy;
	//static int sig_count=0;

	// Use the most recent stat for the new manifest.
	if(manio_write_sbuf(newmanio, sb)) return -1;

	if(!(copy=strdup((*csb)->path)))
	{
		log_out_of_memory(__FUNCTION__);
		return -1;
	}

	while(1)
	{
		if((ars=manio_sbuf_fill(cmanio, *csb, *blk, NULL, conf))<0)
			return -1;
		else if(ars>0)
		{
			// Reached the end.
			*finished=1;
			sbuf_free(*csb); *csb=NULL;
			blk_free(*blk); *blk=NULL;
			free(copy);
			return 0;
		}
		// Got something.
		if(strcmp((*csb)->path, copy))
		{
			// Found the next entry.
			free(copy);
			return 0;
		}

		// Should have the next signature.
		// Write it to the file.
		if(manio_write_sig_and_path(newmanio, *blk))
			break;
	}

	free(copy);
	return -1;
}

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

static int add_to_hooks_list(struct hooks ***hooks, int *h, struct hooks **hnew)
{
	if(!(*hooks=(struct hooks **)realloc(*hooks,
		((*h)+1)*sizeof(struct hooks *))))
	{
		log_out_of_memory(__FUNCTION__);
		return -1;
	}
	
	(*hooks)[(*h)++]=*hnew;
	*hnew=NULL;
	return 0;
}

// Return 0 for OK, -1 for error, 1 for finished reading the file.
static int get_next_set_of_hooks(struct hooks **hnew, struct sbuf *sb, gzFile spzp, char **path, char **fingerprints, const char *sparse, struct config *conf)
{
	int ars;
	while(1)
	{
		if((ars=sbuf_fill_from_gzfile(sb, spzp, NULL, NULL, conf))<0)
			break;
		else if(ars>0)
		{
			// Reached the end.
			if(hooks_alloc(hnew, path, fingerprints))
				break;
			return 1;
		}
		if(sb->cmd==CMD_MANIFEST)
		{
			if(hooks_alloc(hnew, path, fingerprints))
				break;
			if(*fingerprints)
			{
				free(*fingerprints);
				*fingerprints=NULL;
			}
			if(*path) free(*path);
			*path=sb->path;
			sb->path=NULL;
			sbuf_free_contents(sb);
			if(*hnew) return 0;
		}
		else if(sb->cmd==CMD_FINGERPRINT)
		{
			if(astrcat(fingerprints, sb->path))
				break;
			sbuf_free_contents(sb);
		}
		else
		{
			logp("Unexpected line in %s: %c:%s\n",
				sparse, sb->cmd, sb->path);
			break;
		}
	}

	return -1;
}

static int gzprintf_hooks(gzFile tzp, struct hooks *hooks)
{
	static char *f;
	static char ftmp[16+1];
	size_t len=strlen(hooks->fingerprints);

	printf("NW: %c%04lX%s\n", CMD_MANIFEST,
		strlen(hooks->path), hooks->path);
	gzprintf(tzp, "%c%04lX%s\n", CMD_MANIFEST,
		strlen(hooks->path), hooks->path);
	for(f=hooks->fingerprints; f<hooks->fingerprints+len; f+=16)
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

/* Sort all the sparse indexes grouped by manifest file. Looks like:
   M0038testclient/0000001 2013-10-06 06:17:06/manifest/00000021
   F0010F0002FC6B8757464
   F0010F03570783919AD5E
   F0010F042F8D2767B4141
   M0038testclient/0000001 2013-10-06 06:17:06/manifest/00000011
   F0010F00065F673E9F196
   F0010F00731D531BAE08D
   F0010F0490AE87E44FE31
*/
static int sort_sparse_indexes(const char *sparse, struct config *conf)
{
	int h=0;
	int x=0;
	int ars=0;
	int ret=-1;
	gzFile tzp=NULL;
	gzFile spzp=NULL;
	char *tmpfile=NULL;
	struct sbuf *sb=NULL;
	struct hooks *hnew=NULL;
	struct hooks **hooks=NULL;
	char *path=NULL;
	char *fingerprints=NULL;

	if(!(sb=sbuf_alloc())
	  || !(tmpfile=prepend(sparse, "tmp", strlen("tmp"), "."))
	  || !(spzp=gzopen_file(sparse, "rb"))
	  || !(tzp=gzopen_file(tmpfile, "wb")))
		goto end;

	while(1)
	{
		if((ars=get_next_set_of_hooks(&hnew, sb, spzp,
			&path, &fingerprints, sparse, conf))<0)
				goto end;
		if(hnew && add_to_hooks_list(&hooks, &h, &hnew))
			goto end;
		if(ars>0)
		{
			// Finished OK.
			break;
		}
	}

	qsort(hooks, h, sizeof(struct hooks *),
		(int (*)(const void *, const void *))hookscmp);

	for(x=0; x<h; x++)
	{
		// Skip duplicates.
		if(x>0 && !hookscmp(
		  (const struct hooks **)&hooks[x],
		  (const struct hooks **)&hooks[x-1])) continue;

		if(gzprintf_hooks(tzp, hooks[x]))
			goto end;
	}

	if(gzclose_fp(&tzp))
	{
		logp("Error closing %s in %s\n", tmpfile, __FUNCTION__);
		goto end;
	}

	if(do_rename(tmpfile, sparse)) goto end;

	ret=0;
end:
	sbuf_free(sb);
	gzclose_fp(&spzp);
	gzclose_fp(&tzp);
	if(tmpfile) free(tmpfile);
	if(path) free(path);
	if(fingerprints) free(fingerprints);
	for(x=0; x<h; x++) hooks_free(&(hooks[x]));
	if(hooks) free(hooks);
	return ret;
}

/* Merge the new sparse indexes into the global sparse index. */
static int merge_sparse_indexes(const char *global, const char *sparse, struct config *conf)
{
	int ars;
	int fcmp;
	int ret=-1;
	char *path=NULL;
	char *gpath=NULL;
	struct sbuf *gsb=NULL;
	struct sbuf *nsb=NULL;
	char *fingerprints=NULL;
	char *gfingerprints=NULL;
	gzFile tzp=NULL;
	gzFile gzp=NULL;
	gzFile nzp=NULL;
	char *tmpfile=NULL;
	struct hooks *gnew=NULL;
	struct hooks *nnew=NULL;
	struct stat statp;

	if(!(nsb=sbuf_alloc())
	  || !(gsb=sbuf_alloc())
	  || !(tmpfile=prepend(global, "tmp", strlen("tmp"), "."))
	  || !(nzp=gzopen_file(sparse, "rb"))
	  || build_path_w(tmpfile)
	  || !(tzp=gzopen_file(tmpfile, "wb"))
	  || (!lstat(global, &statp) && !(gzp=gzopen_file(global, "rb"))))
		goto end;

	while(gzp || nzp)
	{
		if(gzp
		  && gsb
		  && !gnew
		  && (ars=get_next_set_of_hooks(&gnew, gsb, gzp,
			&gpath, &gfingerprints, global, conf)))
		{
			if(ars<0) goto end;
			// ars==1 means it ended ok.
			gzclose_fp(&gzp);
		}

		if(nzp
		  && nsb
		  && !nnew
		  && (ars=get_next_set_of_hooks(&nnew, nsb, nzp,
			&path, &fingerprints, sparse, conf)))
		{
			if(ars<0) goto end;
			// ars==1 means it ended ok.
			gzclose_fp(&nzp);
		}

		if(gnew && !nnew)
		{
			if(gzprintf_hooks(tzp, gnew)) goto end;
			hooks_free(&gnew);
		}
		else if(!gnew && nnew)
		{
			if(gzprintf_hooks(tzp, nnew)) goto end;
			hooks_free(&nnew);
		}
		else if(!gnew && !nnew)
		{
			continue;
		}
		else if(!(fcmp=hookscmp(
		  (const struct hooks **)&gnew,
		  (const struct hooks **)&nnew)))
		{
			// They were the same - write the new one.
			if(gzprintf_hooks(tzp, nnew)) goto end;
			hooks_free(&gnew);
			hooks_free(&nnew);
		}
		else if(fcmp<0)
		{
			if(gzprintf_hooks(tzp, gnew)) goto end;
			hooks_free(&gnew);
		}
		else
		{
			if(gzprintf_hooks(tzp, nnew)) goto end;
			hooks_free(&nnew);
		}
	}

	if(gzclose_fp(&tzp))
	{
		logp("Error closing %s in %s\n", tmpfile, __FUNCTION__);
		goto end;
	}

	if(do_rename(tmpfile, global)) goto end;

	ret=0;
end:
	gzclose_fp(&tzp);
	gzclose_fp(&gzp);
	gzclose_fp(&nzp);
	sbuf_free(gsb);
	sbuf_free(nsb);
	hooks_free(&gnew);
	hooks_free(&nnew);
	if(path) free(path);
	if(gpath) free(gpath);
	if(fingerprints) free(fingerprints);
	if(gfingerprints) free(gfingerprints);
	if(tmpfile) free(tmpfile);
	return ret;
}

static int sparse_generation(struct manio *newmanio, const char *datadir, const char *manifest_dir, struct config *conf)
{
	int ars;
	int ret=-1;
	gzFile spzp=NULL;
	char *sparse=NULL;
	struct sbuf *sb=NULL;
	char *global_sparse=NULL;
	struct blk *blk=NULL;
	int sig_count=0;
	char *fpath=NULL;

	if(!(sparse=prepend_s(manifest_dir, "sparse"))
	  || !(global_sparse=prepend_s(datadir, "sparse"))
	  || !(sb=sbuf_alloc())
	  || !(blk=blk_alloc())
	  || build_path_w(sparse)
	  || !(spzp=gzopen_file(sparse, "wb")))
		goto end;

	while(1)
	{
		if((ars=manio_sbuf_fill(newmanio, sb, blk, NULL, conf))<0)
			goto end; // Error
		else if(ars>0)
			break; // Finished

		// FIX THIS: I am sure this is not really necessary.
		if(!fpath || strcmp(fpath, newmanio->fpath))
		{
			if(fpath) free(fpath);
			if(!(fpath=strdup(newmanio->fpath)))
			{
				log_out_of_memory(__FUNCTION__);
				goto end;
			}
		}

		if(!*(blk->weak)) continue;

		if(is_hook(blk->weak))
			snprintf(sort_blk[sort_ind++], 16+1, "%s", blk->weak);
		*(blk->weak)='\0';

		// FIX THIS: Also want to make this whole business
		// less fragile.
		if(++sig_count<SIG_MAX) continue;
		sig_count=0;

		if(write_hooks(spzp, fpath, conf)) goto end;
	}

	if(sig_count && write_hooks(spzp, fpath, conf)) goto end;

	if(gzclose_fp(&spzp))
	{
		logp("Error closing %s in %s\n", sparse, __FUNCTION__);
		goto end;
	}

	if(sort_sparse_indexes(sparse, conf)
	  || merge_sparse_indexes(global_sparse, sparse, conf))
		goto end;

	ret=0;
end:
	if(sparse) free(sparse);
	if(global_sparse) free(global_sparse);
	gzclose_fp(&spzp);
	sbuf_free(sb);
	blk_free(blk);
	return ret;
}

// This is basically backup_phase3_server() from burp1. It used to merge the
// unchanged and changed data into a single file. Now it splits the manifests
// into several files.
int phase3(struct manio *chmanio, struct manio *unmanio, const char *manifest_dir, const char *datadir, struct config *conf)
{
	int ars=0;
	int ret=1;
	int pcmp=0;
	struct sbuf *usb=NULL;
	struct sbuf *csb=NULL;
	struct blk *blk=NULL;
	int finished_ch=0;
	int finished_un=0;
	struct manio *newmanio=NULL;

	logp("Start phase3\n");

	if(!(newmanio=manio_alloc())
	  || manio_init_write(newmanio, manifest_dir)
	  || !(usb=sbuf_alloc())
	  || !(csb=sbuf_alloc()))
		goto end;

	while(!finished_ch || !finished_un)
	{
		if(!blk && !(blk=blk_alloc())) return -1;

		if(!finished_un
		  && usb
		  && !usb->path
		  && (ars=manio_sbuf_fill(unmanio, usb, NULL, NULL, conf)))
		{
			if(ars<0) goto end; // Error.
			finished_un=1; // OK.
		}

		if(!finished_ch
		  && csb
		  && !csb->path
		  && (ars=manio_sbuf_fill(chmanio, csb, NULL, NULL, conf)))
		{
			if(ars<0) goto end; // Error.
			finished_ch=1; // OK.
		}

		if((usb && usb->path) && (!csb || !csb->path))
		{
			if(copy_unchanged_entry(&usb, usb, &finished_un,
				&blk, unmanio, newmanio, manifest_dir,
				conf)) goto end;
		}
		else if((!usb || !usb->path) && (csb && csb->path))
		{
			if(copy_unchanged_entry(&csb, csb, &finished_ch,
				&blk, chmanio, newmanio, manifest_dir,
				conf)) goto end;
		}
		else if((!usb || !usb->path) && (!csb || !(csb->path)))
		{
			continue;
		}
		else if(!(pcmp=sbuf_pathcmp(usb, csb)))
		{
			// They were the same - write one.
			if(copy_unchanged_entry(&csb, csb, &finished_ch,
				&blk, chmanio, newmanio, manifest_dir,
				conf)) goto end;
		}
		else if(pcmp<0)
		{
			if(copy_unchanged_entry(&usb, usb, &finished_un,
				&blk, unmanio, newmanio, manifest_dir,
				conf)) goto end;
		}
		else
		{
			if(copy_unchanged_entry(&csb, csb, &finished_ch,
				&blk, chmanio, newmanio, manifest_dir,
				conf)) goto end;
		}
	}

	// Flush to disk and set up for reading.
	if(manio_set_mode_read(newmanio))
	{
		logp("Error setting %s to read in %s\n",
			newmanio->directory, __FUNCTION__);
		goto end;
	}

	if(sparse_generation(newmanio, datadir, manifest_dir, conf))
		goto end;

//	Delete all from changed here.
//	Delete all from unchanged here.

	ret=0;

	logp("End phase3\n");
end:
	manio_close(newmanio);
	manio_close(chmanio);
	manio_close(unmanio);
	sbuf_free(csb);
	sbuf_free(usb);
	blk_free(blk);
	return ret;
}
