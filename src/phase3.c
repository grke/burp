#include "burp.h"
#include "prog.h"
#include "base64.h"
#include "msg.h"
#include "lock.h"
#include "handy.h"
#include "asyncio.h"
#include "counter.h"
#include "dpth.h"
#include "sbuf.h"
#include "auth_server.h"
#include "backup_server.h"
#include "current_backups_server.h"
#include "attribs.h"
#include "hash.h"
#include "phase3.h"
#include "handy.h"

static char sort_blk[SIG_MAX][16+1];
static int sort_ind=0;

static char *get_next_tmp_path(const char *manifest)
{
	static char tmp[32];
	static uint64_t count=0;
	snprintf(tmp, sizeof(tmp), "%08lX", count++);
	return tmp;
}

static gzFile get_new_manifest(const char *manifest, const char *rmanifest, gzFile spzp, struct config *conf)
{
	char *tmp;
	const char *cp;
	gzFile zp=NULL;
	char *man_path=NULL;
	if(!(tmp=get_next_tmp_path(manifest)))
		return NULL;

	if(!(man_path=prepend_s(manifest, tmp, sizeof(tmp)))
	  || !(zp=gzopen_file(man_path, comp_level(conf))))
	{
		if(man_path) free(man_path);
		return NULL;
	}
	// Make sure the path to this manifest in the sparse index file is
	// relative (does not start with a slash), and that it is the real path
	// (not the symlinked 'working' path).
	cp=rmanifest+strlen(conf->directory);
	while(cp && *cp=='/') cp++;
	gzprintf(spzp, "%c%04X%s/%s\n", CMD_MANIFEST,
		strlen(cp)+strlen(tmp)+1, cp, tmp);
	free(man_path);
	return zp;
}

static int write_hooks(const char *sparse, gzFile spzp)
{
	int i=0;
	if(!sort_ind) return 0;
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

static int copy_unchanged_entry(struct sbuf **csb, struct sbuf *sb, struct blk **blk, gzFile *cmanzp, gzFile *mzp, gzFile spzp, const char *manifest, const char *rmanifest, const char *sparse, struct config *conf)
{
	static int ars;
	static char *copy;
	static int sig_count=0;

	if(!*mzp && !(*mzp=get_new_manifest(manifest,
		rmanifest, spzp, conf)))
			return -1;

	// Use the most recent stat for the new manifest.
	if(sbuf_to_manifest(sb, *mzp)) return -1;

	if(!(copy=strdup((*csb)->path)))
	{
		log_out_of_memory(__FUNCTION__);
		return -1;
	}

	while(1)
	{
		if((ars=sbuf_fill_from_gzfile(*csb,
			*cmanzp, *blk, NULL, conf))<0) return -1;
		else if(ars>0)
		{
			// Reached the end.

			sbuf_free(*csb);
			blk_free(*blk);
			*csb=NULL;
			*blk=NULL;
			gzclose_fp(cmanzp);
			//gzclose_fp(mzp);
			free(copy);
			return 0;
		}
		else
		{
			// Got something.
			if(strcmp((*csb)->path, copy))
			{
				// Found the next entry.
				free(copy);
				return 0;
			}

			if(!*mzp && !(*mzp=get_new_manifest(manifest,
				rmanifest, spzp, conf)))
					break;
			// Should have the next signature.
			// Write it to the unchanged file.
			gzprintf_sig_and_path(*mzp, *blk);

			// FIX THIS: Should be checking bits on
			// blk->fingerprint, rather than a character.
			if(*((*blk)->weak)=='F')
			{
				snprintf(sort_blk[sort_ind++], 16+1,
					(*blk)->weak);
			}

			if(++sig_count>SIG_MAX)
			{
				sig_count=0;
				gzclose_fp(mzp);
				if(write_hooks(sparse, spzp))
					break;
			}
		}
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

// This is basically backup_phase3_server() from burp1. It used to merge the
// unchanged and changed data into a single file. Now it splits the manifests
// into several files.
int phase3(const char *changed, const char *unchanged, const char *manifest, const char *rmanifest, const char *datadir, struct config *conf)
{
	int ars=0;
	int ret=1;
	int pcmp=0;
	gzFile mzp=NULL;
	gzFile chzp=NULL;
	gzFile unzp=NULL;
	gzFile spzp=NULL;
	struct sbuf *usb=NULL;
	struct sbuf *csb=NULL;
	struct blk *blk=NULL;
	char *sparse=NULL;
	char *global_sparse=NULL;

	logp("Start phase3\n");

	if(!(sparse=prepend_s(manifest, "sparse", strlen("sparse")))
	  || !(global_sparse=prepend_s(datadir, "sparse", strlen("sparse")))
	  || build_path_w(sparse)
	  || !(usb=sbuf_alloc())
	  || !(csb=sbuf_alloc())
	  || !(chzp=gzopen_file(changed, "rb"))
	  || !(unzp=gzopen_file(unchanged, "rb"))
	  || !(spzp=gzopen_file(sparse, "wb")))
		goto end;

	while(unzp || chzp)
	{
		if(!blk && !(blk=blk_alloc())) return -1;

		if(unzp
		  && usb
		  && !usb->path
		  && (ars=sbuf_fill_from_gzfile(usb, unzp, NULL, NULL, conf)))
		{
			if(ars<0) goto end;
			// ars==1 means it ended ok.
			gzclose_fp(&unzp);
		}

		if(chzp
		  && csb
		  && !csb->path
		  && (ars=sbuf_fill_from_gzfile(csb, chzp, NULL, NULL, conf)))
		{
			if(ars<0) goto end;
			// ars==1 means it ended ok.
			gzclose_fp(&chzp);
		}

		if((usb && usb->path) && (!csb || !csb->path))
		{
			if(copy_unchanged_entry(&usb, usb,
				&blk, &unzp, &mzp, spzp,
				manifest, rmanifest, sparse, conf)) goto end;
		}
		else if((!usb || !usb->path) && (csb && csb->path))
		{
			if(copy_unchanged_entry(&csb, csb,
				&blk, &chzp, &mzp, spzp,
				manifest, rmanifest, sparse, conf)) goto end;
		}
		else if((!usb || !usb->path) && (!csb || !(csb->path)))
		{
			continue;
		}
		else if(!(pcmp=sbuf_pathcmp(usb, csb)))
		{
			// They were the same - write one.
			if(copy_unchanged_entry(&csb, csb,
				&blk, &chzp, &mzp, spzp,
				manifest, rmanifest, sparse, conf)) goto end;
		}
		else if(pcmp<0)
		{
			if(copy_unchanged_entry(&usb, usb,
				&blk, &unzp, &mzp, spzp,
				manifest, rmanifest, sparse, conf)) goto end;
		}
		else
		{
			if(copy_unchanged_entry(&csb, csb,
				&blk, &chzp, &mzp, spzp,
				manifest, rmanifest, sparse, conf)) goto end;
		}
	}

	if(gzclose_fp(&mzp))
	{
		logp("Error closing %s in %s\n", manifest, __FUNCTION__);
		goto end;
	}

	if(spzp && write_hooks(sparse, spzp))
		goto end;
	if(gzclose_fp(&spzp))
	{
		logp("Error closing %s in %s\n", sparse, __FUNCTION__);
		goto end;
	}

	unlink(changed);
	unlink(unchanged);

	if(sort_sparse_indexes(sparse, conf)
	  || merge_sparse_indexes(global_sparse, sparse, conf))
		goto end;

	ret=0;

	logp("End phase3\n");
end:
	gzclose_fp(&mzp);
	gzclose_fp(&chzp);
	gzclose_fp(&unzp);
	gzclose_fp(&spzp);
	sbuf_free(csb);
	sbuf_free(usb);
	blk_free(blk);
	if(sparse) free(sparse);
	if(global_sparse) free(global_sparse);
	return ret;
}
