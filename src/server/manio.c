#include "include.h"
#include "../cmd.h"
#include "../hexmap.h"
#include "protocol2/champ_chooser/include.h"

#define MANIO_MODE_READ		"rb"
#define MANIO_MODE_WRITE	"wb"

#define WEAK_LEN		16
#define WEAK_STR_LEN		WEAK_LEN+1
#define MSAVE_PATH_LEN		14

struct manio *manio_alloc(void)
{
	return (struct manio *)calloc_w(1, sizeof(struct manio), __func__);
}

static int manio_free_content(struct manio *manio)
{
	int ret=0;
	if(!manio) return ret;
	if(manio_close(manio)) ret=-1;
	free_w(&manio->base_dir);
	free_w(&manio->directory);
	free_w(&manio->fpath);
	free_w(&manio->lpath);
	free_w(&manio->mode);
	free_w(&manio->hook_dir);
	free_w(&manio->rdirectory);
	if(manio->hook_sort)
	{
		int i;
		for(i=0; i<MANIFEST_SIG_MAX; i++)
			free_w(&(manio->hook_sort[i]));
		free_v((void **)&manio->hook_sort);
	}
	memset(manio, 0, sizeof(struct manio));
	return ret;
}

static int write_hook_header(struct manio *manio,
	struct fzp *fzp, const char *comp)
{
	const char *cp;
	char *tmp=NULL;
	cp=manio->rdirectory+strlen(manio->base_dir);
	while(cp && *cp=='/') cp++;
	if(!(tmp=prepend_s(cp, comp))) return -1;
	// FIX THIS: fzp_printf will truncate at 512 characters.
	fzp_printf(fzp, "%c%04X%s\n", CMD_MANIFEST, strlen(tmp), tmp);
	free_w(&tmp);
	return 0;
}

static int strsort(const void *a, const void *b)
{
	const char *x=*(const char**)a;
	const char *y=*(const char**)b;
	return strcmp(x, y);
}

static char *get_fcount_path(struct manio *manio)
{
	return prepend_s(manio->directory, "fcount");
}

// Backup phase4 needs to know the fcount, so leave a file behind that
// contains it (otherwise phase4 will have to read and sort the directory
// contents).
static int manio_write_fcount(struct manio *manio)
{
	int ret=-1;
	FILE *fp=NULL;
	char *path=NULL;

	if(!(path=get_fcount_path(manio))
	  || !(fp=open_file(path, "wb")))
		goto end;
	if(fprintf(fp, "%08"PRIX64"\n", manio->fcount)!=9)
	{
		logp("Short write when writing to %s\n", path);
		goto end;
	}
	ret=0;
end:
	if(close_fp(&fp))
	{
		logp("Could not close file pointer to %s\n", path);
		ret=-1;
	}
	free_w(&path);
	return ret;
}

int manio_read_fcount(struct manio *manio)
{
	int ret=-1;
	size_t s;
	FILE *fp=NULL;
	char *path=NULL;
	char buf[16]="";
	if(!(path=get_fcount_path(manio))
	  || !(fp=open_file(path, "rb")))
		goto end;
	if(!fgets(buf, sizeof(buf), fp))
	{
		logp("fgets on %s failed\n", path);
		goto end;
	}
	s=strlen(buf);
	if(s!=9)
	{
		logp("data in %s is not the right length (%s!=9)\n", s);
		goto end;
	}
	manio->fcount=strtoul(buf, NULL, 16);
	ret=0;
end:
	close_fp(&fp);
	free_w(&path);
	return ret;
}

static int sort_and_write_hooks(struct manio *manio)
{
	int i;
	int ret=-1;
	struct fzp *fzp=NULL;
	char comp[32]="";
	char *path=NULL;
	int hook_count=manio->hook_count;
	char **hook_sort=manio->hook_sort;
	if(!hook_sort) return 0;

	snprintf(comp, sizeof(comp), "%08"PRIX64, manio->fcount-1);
	if(!(path=prepend_s(manio->hook_dir, comp))
	  || build_path_w(path)
	  || !(fzp=fzp_gzopen(path, manio->mode)))
		goto end;

	qsort(hook_sort, hook_count, sizeof(char *), strsort);

	if(write_hook_header(manio, fzp, comp)) goto end;
	for(i=0; i<hook_count; i++)
	{
		// Do not bother with duplicates.
		if(i && !strcmp(hook_sort[i],
			hook_sort[i-1])) continue;
		fzp_printf(fzp, "%c%04X%s\n", CMD_FINGERPRINT,
			(unsigned int)strlen(hook_sort[i]), hook_sort[i]);
	}
	if(fzp_close(&fzp))
	{
		logp("Error closing %s in %s: %s\n",
			path, __func__, strerror(errno));
		goto end;
	}
	if(manio_write_fcount(manio)) goto end;
	manio->hook_count=0;
	ret=0;
end:
	fzp_close(&fzp);
	free_w(&path);
	return ret;
}

static int sort_and_write_dindex(struct manio *manio)
{
	int i;
	int ret=-1;
	struct fzp *fzp=NULL;
	char comp[32]="";
	char *path=NULL;
	int dindex_count=manio->dindex_count;
	char **dindex_sort=manio->dindex_sort;
	if(!dindex_sort) return 0;

	snprintf(comp, sizeof(comp), "%08"PRIX64, manio->fcount-1);
	if(!(path=prepend_s(manio->dindex_dir, comp))
	  || build_path_w(path)
	  || !(fzp=fzp_gzopen(path, manio->mode)))
		goto end;

	qsort(dindex_sort, dindex_count, sizeof(char *), strsort);

	for(i=0; i<dindex_count; i++)
	{
		// Do not bother with duplicates.
		if(i && !strcmp(dindex_sort[i],
			dindex_sort[i-1])) continue;
		fzp_printf(fzp, "%c%04X%s\n", CMD_FINGERPRINT,
			(unsigned int)strlen(dindex_sort[i]), dindex_sort[i]);
	}
	if(fzp_close(&fzp))
	{
		logp("Error closing %s in %s: %s\n",
			path, __func__, strerror(errno));
		goto end;
	}
	manio->dindex_count=0;
	ret=0;
end:
	fzp_close(&fzp);
	free_w(&path);
	return ret;
}

int manio_close(struct manio *manio)
{
	if(manio_closed(manio)) return 0;
	if(sort_and_write_hooks(manio)
	  || sort_and_write_dindex(manio))
	{
		fzp_close(&(manio->fzp));
		return -1;
	}
	return fzp_close(&(manio->fzp));
}

int manio_free(struct manio **manio)
{
	int ret=0;
	if(!manio || !*manio) return ret;
	if(manio_free_content(*manio)) ret=-1;
	free_v((void **)manio);
	return ret;
}

static int manio_set_mode(struct manio *manio, const char *mode)
{
	if(manio_close(manio)) return -1;
	free_w(&manio->mode);
	if(!(manio->mode=strdup_w(mode, __func__)))
		return -1;
	manio->fcount=0;
	return 0;
}

int manio_set_mode_read(struct manio *manio)
{
	return manio_set_mode(manio, MANIO_MODE_READ);
}

int manio_set_mode_write(struct manio *manio)
{
	return manio_set_mode(manio, MANIO_MODE_WRITE);
}

void manio_set_protocol(struct manio *manio, enum protocol protocol)
{
	manio->protocol=protocol;
}

static int manio_init(struct manio *manio, const char *directory, const char *mode)
{
	if(manio_free_content(manio)) return -1;
	if(!(manio->directory=strdup_w(directory, __func__)))
		return -1;
	if(manio_set_mode(manio, mode)) return -1;
	manio_set_protocol(manio, PROTO_2);
	return 0;
}

int manio_init_read(struct manio *manio, const char *directory)
{
	return manio_init(manio, directory, MANIO_MODE_READ);
}

int manio_init_write(struct manio *manio, const char *directory)
{
	return manio_init(manio, directory, MANIO_MODE_WRITE);
}

static char *get_next_fpath_protocol1(struct manio *manio)
{
	return strdup_w(manio->directory, __func__);
}

static char *get_next_fpath(struct manio *manio)
{
	static char tmp[32];
	if(manio->protocol==PROTO_1) return get_next_fpath_protocol1(manio);
	snprintf(tmp, sizeof(tmp), "%08"PRIX64, manio->fcount++);
	return prepend_s(manio->directory, tmp);
}

int manio_open_next_fpath(struct manio *manio)
{
	static struct stat statp;

	free_w(&manio->lpath);
	manio->lpath=manio->fpath;
	if(!(manio->fpath=get_next_fpath(manio))) return -1;

	if(!strcmp(manio->mode, MANIO_MODE_READ)
	  && lstat(manio->fpath, &statp))
		return 0;

	if(build_path_w(manio->fpath)
	  || !(manio->fzp=fzp_gzopen(manio->fpath, manio->mode)))
		return -1;
	return 0;
}

// Return -1 for error, 0 for stuff read OK, 1 for end of files.
static int do_manio_sbuf_fill(struct manio *manio, struct asfd *asfd,
	struct sbuf *sb, struct blk *blk,
	struct sdirs *sdirs, struct conf **confs, int phase1)
{
	int ars;

	while(1)
	{
		if(!manio->fzp)
		{
			if(manio_open_next_fpath(manio)) goto error;
			if(!manio->fzp) return 1; // No more files to read.
		}

		if(manio->protocol==PROTO_2 || phase1)
		{
			ars=sbuf_fill(sb, asfd, manio->fzp, blk,
				sdirs?sdirs->data:NULL, confs);
		}
		else
		{
			ars=sbufl_fill(sb, asfd, manio->fzp, confs);
		}
		switch(ars)
		{
			case 0: return 0; // Got something.
			case 1: break; // Keep going.
			default: goto error; // Error.
		}

		// Reached the end of the current file.
		// Maybe there is another file to continue with.
		if(manio_close(manio)) goto error;

		// If in protocol1 mode, there is only one file, so end.
		if(manio->protocol==PROTO_1) return 1;
	}

error:
	manio_close(manio);
	return -1;
}

int manio_sbuf_fill(struct manio *manio, struct asfd *asfd,
	struct sbuf *sb, struct blk *blk,
	struct sdirs *sdirs, struct conf **confs)
{
	return do_manio_sbuf_fill(manio, asfd, sb, blk, sdirs, confs, 0);
}

// FIX THIS:
// Same as manio_sbuf_fill(), but always does sbuf_fill_from_gzfile().
// Protocol2 is using the burp-1 phase1 format. If it wrote its own format,
// this separate function should not be necessary.
// Once there are some tests that excercise the resume functionality, then
// this can be dealt with more safely.
int manio_sbuf_fill_phase1(struct manio *manio, struct asfd *asfd,
	struct sbuf *sb, struct blk *blk,
	struct sdirs *sdirs, struct conf **confs)
{
	return do_manio_sbuf_fill(manio, asfd, sb, blk, sdirs, confs, 1);
}

static int reset_sig_count_and_close(struct manio *manio)
{
	if(manio_close(manio)) return -1;
	manio->sig_count=0;
	return 0;
}

#define TOCHECK	4
static int manio_find_boundary(const char *msg)
{
	int i;
	int j;
	// I am currently making it look for four of the same consecutive
	// characters in the signature.
	for(i=0; i<16+32-TOCHECK+1; )
	{
		for(j=1; j<TOCHECK; j++)
			if(msg[i]!=msg[i+j]) { i+=j+1; break; }
		if(j==TOCHECK)
			return 1;
	}
	return 0;
}

// After conditions are met, close the file currently being written to.
// Allow the number of signatures to be vary between MANIFEST_SIG_MIN and
// MANIFEST_SIG_MAX. This will hopefully allow fewer candidate manifests
// generated, since the boundary will be able to vary.
static int check_sig_count(struct manio *manio, const char *msg)
{
	manio->sig_count++;

	if(manio->sig_count<MANIFEST_SIG_MIN)
		return 0; // Not yet time to close.

	if(manio->sig_count>=MANIFEST_SIG_MAX)
		return reset_sig_count_and_close(manio); // Time to close.

	// At this point, dynamically decide based on the current msg.
	if(manio_find_boundary(msg))
		return reset_sig_count_and_close(manio); // Time to close.
	return 0;
}

static int write_sig_msg(struct manio *manio, const char *msg)
{
	if(!manio->fzp && manio_open_next_fpath(manio)) return -1;
	if(send_msg_fzp(manio->fzp, CMD_SIG, msg, strlen(msg))) return -1;
	return check_sig_count(manio, msg);
}

static char *sig_to_msg(struct blk *blk, int save_path)
{
	static char msg[128];
	snprintf(msg, sizeof(msg),
		"%016"PRIX64 "%s%s",
		blk->fingerprint,
		bytes_to_md5str(blk->md5sum),
		save_path?bytes_to_savepathstr_with_sig(blk->savepath):"");
	return msg;
}

int manio_write_sig(struct manio *manio, struct blk *blk)
{
	return write_sig_msg(manio, sig_to_msg(blk, 0 /* no save_path */));
}

int manio_write_sig_and_path(struct manio *manio, struct blk *blk)
{
	if(manio->hook_sort && is_hook(blk->fingerprint))
	{
		// Add to list of hooks for this manifest chunk.
		snprintf(manio->hook_sort[manio->hook_count++], WEAK_STR_LEN,
			"%016"PRIX64,
			blk->fingerprint);
	}
	if(manio->dindex_sort)
	{
		char *savepathstr=bytes_to_savepathstr(blk->savepath);
		// Ignore obvious duplicates.
		if(!manio->hook_count
		  || strncmp(manio->dindex_sort[manio->hook_count-1],
			savepathstr, MSAVE_PATH_LEN))
		{
			// Add to list of dindexes for this manifest chunk.
			snprintf(manio->dindex_sort[manio->dindex_count++],
				MSAVE_PATH_LEN, "%s", savepathstr);
		}
	}
	return write_sig_msg(manio, sig_to_msg(blk, 1 /* save_path */));
}

int manio_write_sbuf(struct manio *manio, struct sbuf *sb)
{
	if(!manio->fzp && manio_open_next_fpath(manio)) return -1;
	return sbuf_to_manifest(sb, manio->fzp);
}

int manio_closed(struct manio *manio)
{
	if(manio->fzp || !manio->fpath) return 0;
	return 1;
}

int manio_init_write_hooks(struct manio *manio,
	const char *base_dir, const char *hook_dir, const char *rdirectory)
{
	int i=0;
	if(!(manio->base_dir=strdup_w(base_dir, __func__))
	  || !(manio->hook_dir=strdup_w(hook_dir, __func__))
	  || !(manio->rdirectory=strdup_w(rdirectory, __func__))
	  || !(manio->hook_sort=
		(char **)calloc_w(MANIFEST_SIG_MAX, sizeof(char*), __func__)))
			return -1;
	for(i=0; i<MANIFEST_SIG_MAX; i++)
		if(!(manio->hook_sort[i]=
			(char *)calloc_w(1, WEAK_STR_LEN, __func__)))
				return -1;
	return 0;
}

int manio_init_write_dindex(struct manio *manio, const char *dir)
{
	int i=0;
	if(!(manio->dindex_dir=strdup_w(dir, __func__))
	  || !(manio->dindex_sort=
		(char **)calloc_w(MANIFEST_SIG_MAX, sizeof(char*), __func__)))
			return -1;
	for(i=0; i<MANIFEST_SIG_MAX; i++)
		if(!(manio->dindex_sort[i]=
			(char *)calloc_w(1, MSAVE_PATH_LEN+1, __func__)))
				return -1;
	return 0;
}

// Return -1 on error, 0 on OK, 1 for srcmanio finished.
int manio_copy_entry(struct asfd *asfd, struct sbuf **csb, struct sbuf *sb,
	struct blk **blk, struct manio *srcmanio,
	struct manio *dstmanio, struct conf **confs)
{
	static int ars;
	static char *copy=NULL;

	// Use the most recent stat for the new manifest.
	if(dstmanio && manio_write_sbuf(dstmanio, sb)) goto error;

	if(!(copy=strdup_w((*csb)->path.buf, __func__)))
		goto error;

	while(1)
	{
		if((ars=manio_sbuf_fill(srcmanio, asfd, *csb,
			*blk, NULL, confs))<0) goto error;
		else if(ars>0)
		{
			// Finished.
			sbuf_free(csb);
			blk_free(blk);
			free_w(&copy);
			return 1;
		}

		// Got something.
		if(strcmp((*csb)->path.buf, copy))
		{
			// Found the next entry.
			free_w(&copy);
			return 0;
		}
		// Should have the next signature.
		// Write it to the destination manifest.
		if(dstmanio && manio_write_sig_and_path(dstmanio, *blk))
			goto error;
	}

error:
	free_w(&copy);
	return -1;
}

int manio_forward_through_sigs(struct asfd *asfd,
	struct sbuf **csb, struct blk **blk,
	struct manio *manio, struct conf **confs)
{
	// Call manio_copy_entry with nothing to write to, so
	// that we forward through the sigs in manio.
	return manio_copy_entry(asfd, csb, NULL, blk, manio, NULL, confs);
}

off_t manio_tell(struct manio *manio)
{
	if(!manio->fzp) return 0;
	return fzp_tell(manio->fzp);
}

int manio_seek(struct manio *manio, off_t offset, int whence)
{
	if(!manio->fzp) return 0;
	return fzp_seek(manio->fzp, offset, whence);
}

int manio_truncate(struct manio *manio)
{
	off_t pos=0;
	if(manio->fzp && (pos=fzp_tell(manio->fzp))<0)
	{
		logp("Could not fzp_tell %s in %s(): %s\n",
			manio->directory, __func__, strerror(errno));
		return -1;
	}
	if(truncate(manio->directory, pos))
	{
		logp("Could not truncate %s in %s(): %s\n",
			manio->directory, __func__, strerror(errno));
		return -1;
	}
	return 0;
}
