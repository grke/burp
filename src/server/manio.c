#include "include.h"
#include "../cmd.h"
#include "../hexmap.h"
#include "protocol2/champ_chooser/include.h"
#include "protocol2/dpth.h"

#define MANIO_MODE_READ		"rb"
#define MANIO_MODE_WRITE	"wb"
#define MANIO_MODE_APPEND	"ab"

#define WEAK_LEN		16
#define WEAK_STR_LEN		WEAK_LEN+1
#define MSAVE_PATH_LEN		14

static void man_off_t_free_content(man_off_t *offset)
{
	if(!offset) return;
	free_w(&offset->fpath);
}

void man_off_t_free(man_off_t **offset)
{
	if(!offset || !*offset) return;
	man_off_t_free_content(*offset);
	free_v((void **)offset);
}

static man_off_t *man_off_t_alloc(void)
{
	return (man_off_t *)calloc_w(1, sizeof(man_off_t), __func__);
}

static int init_write_hooks(struct manio *manio,
	const char *hook_dir, const char *rmanifest)
{
	int i=0;
	if(!(manio->hook_dir=strdup_w(hook_dir, __func__))
	  || !(manio->rmanifest=strdup_w(rmanifest, __func__))
	  || !(manio->hook_sort=
		(char **)calloc_w(MANIFEST_SIG_MAX, sizeof(char*), __func__)))
			return -1;
	for(i=0; i<MANIFEST_SIG_MAX; i++)
		if(!(manio->hook_sort[i]=
			(char *)calloc_w(1, WEAK_STR_LEN, __func__)))
				return -1;
	return 0;
}

static int init_write_dindex(struct manio *manio, const char *dir)
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

static int is_single_file(struct manio *manio)
{
	return manio->protocol==PROTO_1 || manio->phase==1;
}

static char *get_next_fpath(struct manio *manio, man_off_t *offset)
{
	static char tmp[32];
	if(is_single_file(manio))
		return strdup_w(manio->manifest, __func__);
	snprintf(tmp, sizeof(tmp), "%08"PRIX64, offset->fcount++);
	return prepend_s(manio->manifest, tmp);
}

static int manio_open_next_fpath(struct manio *manio)
{
	static struct stat statp;

	free_w(&manio->offset->fpath);
	if(!(manio->offset->fpath=get_next_fpath(manio, manio->offset)))
		return -1;

	if(!strcmp(manio->mode, MANIO_MODE_READ)
	  && lstat(manio->offset->fpath, &statp))
		return 0;

	if(build_path_w(manio->offset->fpath))
		return -1;
	switch(manio->phase)
	{
		case 2:
			if(!(manio->fzp=fzp_open(manio->offset->fpath,
				manio->mode))) return -1;
			return 0;
		case 1:
		case 3:
		default:
			if(!(manio->fzp=fzp_gzopen(manio->offset->fpath,
				manio->mode))) return -1;
			return 0;
	}
}

static int manio_open_last_fpath(struct manio *manio)
{
	int max=-1;
	if(is_single_file(manio))
		return manio_open_next_fpath(manio);
	if(get_highest_entry(manio->manifest, &max))
		return -1;
	if(max<0) max=0;
	manio->offset->fcount=(uint64_t)max;
	return manio_open_next_fpath(manio);
}

static struct manio *manio_alloc(void)
{
	return (struct manio *)calloc_w(1, sizeof(struct manio), __func__);
}

static struct manio *do_manio_open(const char *manifest, const char *mode,
	enum protocol protocol, int phase)
{
	struct manio *manio=NULL;
	if(!(manio=manio_alloc())
	  || !(manio->manifest=strdup_w(manifest, __func__))
	  || !(manio->mode=strdup_w(mode, __func__))
	  || !(manio->offset=man_off_t_alloc()))
		goto error;
	manio->protocol=protocol;
	manio->phase=phase;
	if(!strcmp(manio->mode, MANIO_MODE_APPEND))
	{
		if(manio->phase!=2)
		{
			logp("manio append mode only works for phase 2.\n");
			logp("%s has phase: %s\n",
				manio->manifest, manio->phase);
			goto error;
		}
		if(manio_open_last_fpath(manio))
			goto error;
	}
	else
	{
		if(manio_open_next_fpath(manio))
			goto error;
	}
	return manio;
error:
	manio_close(&manio);
	return NULL;
}

struct manio *manio_open(const char *manifest, const char *mode,
	enum protocol protocol)
{
	return do_manio_open(manifest, mode, protocol, 0);
}

struct manio *manio_open_phase1(const char *manifest, const char *mode,
	enum protocol protocol)
{
	return do_manio_open(manifest, mode, protocol, 1);
}

struct manio *manio_open_phase2(const char *manifest, const char *mode,
	enum protocol protocol)
{
	return do_manio_open(manifest, mode, protocol, 2);
}

struct manio *manio_open_phase3(const char *manifest, const char *mode,
	enum protocol protocol, const char *rmanifest)
{
	struct manio *manio=NULL;

	if(!(manio=do_manio_open(manifest, mode, protocol, 3)))
		goto end;

	if(protocol==PROTO_2 && rmanifest)
	{
		char *hooksdir=NULL;
		char *dindexdir=NULL;
		if(!(hooksdir=prepend_s(manifest, "hooks"))
		  || !(dindexdir=prepend_s(manifest, "dindex"))
		  || init_write_hooks(manio, hooksdir, rmanifest)
		  || init_write_dindex(manio, dindexdir))
			manio_close(&manio);
		free_w(&hooksdir);
		free_w(&dindexdir);
	}

end:
	return manio;
}

static void manio_free_content(struct manio *manio)
{
	if(!manio) return;
	man_off_t_free(&manio->offset);
	free_w(&manio->manifest);
	free_w(&manio->mode);
	free_w(&manio->hook_dir);
	free_w(&manio->rmanifest);
	if(manio->hook_sort)
	{
		int i;
		for(i=0; i<MANIFEST_SIG_MAX; i++)
			free_w(&(manio->hook_sort[i]));
		free_v((void **)&manio->hook_sort);
	}
	memset(manio, 0, sizeof(struct manio));
}

static int write_hook_header(struct manio *manio,
	struct fzp *fzp, const char *comp)
{
	char *tmp=NULL;
	if(!(tmp=prepend_s(manio->rmanifest, comp))) return -1;
	// FIX THIS: fzp_printf will truncate at 512 characters.
	fzp_printf(fzp, "%c%04X%s\n", CMD_MANIFEST, strlen(tmp), tmp);
	free_w(&tmp);
	return 0;
}

static int strsort(const void *a, const void *b)
{
	const char *x=*(const char **)a;
	const char *y=*(const char **)b;
	return strcmp(x, y);
}

static char *get_fcount_path(struct manio *manio)
{
	return prepend_s(manio->manifest, "fcount");
}

// Backup phase4 needs to know the fcount, so leave a file behind that
// contains it (otherwise phase4 will have to read and sort the directory
// contents).
static int manio_write_fcount(struct manio *manio)
{
	int ret=-1;
	struct fzp *fzp=NULL;
	char *path=NULL;

	if(!(path=get_fcount_path(manio))
	  || !(fzp=fzp_open(path, "wb")))
		goto end;
	if(fzp_printf(fzp, "%08"PRIX64"\n", manio->offset->fcount)!=9)
	{
		logp("Short write when writing to %s\n", path);
		goto end;
	}
	ret=0;
end:
	if(fzp_close(&fzp))
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
	struct fzp *fzp=NULL;
	char *path=NULL;
	char buf[16]="";
	if(!(path=get_fcount_path(manio))
	  || !(fzp=fzp_open(path, "rb")))
		goto end;
	if(!fzp_gets(fzp, buf, sizeof(buf)))
	{
		logp("fzp_gets on %s failed\n", path);
		goto end;
	}
	s=strlen(buf);
	if(s!=9)
	{
		logp("data in %s is not the right length (%s!=9)\n", s);
		goto end;
	}
	manio->offset->fcount=strtoul(buf, NULL, 16);
	ret=0;
end:
	fzp_close(&fzp);
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

	snprintf(comp, sizeof(comp), "%08"PRIX64, manio->offset->fcount-1);
	if(!(path=prepend_s(manio->hook_dir, comp))
	  || build_path_w(path)
	  || !(fzp=fzp_gzopen(path, MANIO_MODE_WRITE)))
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

	snprintf(comp, sizeof(comp), "%08"PRIX64, manio->offset->fcount-1);
	if(!(path=prepend_s(manio->dindex_dir, comp))
	  || build_path_w(path)
	  || !(fzp=fzp_gzopen(path, MANIO_MODE_WRITE)))
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

static int sort_and_write_hooks_and_dindex(struct manio *manio)
{
	return sort_and_write_hooks(manio)
	  || sort_and_write_dindex(manio);
}

int manio_close(struct manio **manio)
{
	int ret=0;
	if(!manio || !*manio) return ret;
	if(sort_and_write_hooks_and_dindex(*manio)
	  || fzp_close(&((*manio)->fzp)))
		ret=-1;
	manio_free_content(*manio);
	free_v((void **)manio);
	return ret;
}

// Return -1 for error, 0 for stuff read OK, 1 for end of files.
int manio_read_with_blk(struct manio *manio,
	struct sbuf *sb, struct blk *blk,
	struct sdirs *sdirs, struct conf **confs)
{
	while(1)
	{
		if(!manio->fzp)
		{
			if(manio_open_next_fpath(manio)) goto error;
			if(!manio->fzp) return 1; // No more files to read.
		}

		switch(sbuf_fill_from_file(sb, manio->fzp, blk,
			sdirs?sdirs->data:NULL, confs))
		{
			case 0: return 0; // Got something.
			case 1: break; // Keep going.
			default: goto error; // Error.
		}

		// Reached the end of the current file.
		// Maybe there is another file to continue with.
		if(sort_and_write_hooks_and_dindex(manio)
		  || fzp_close(&manio->fzp)) goto error;

		if(is_single_file(manio)) return 1;
	}

error:
	return -1;
}

int manio_read(struct manio *manio, struct sbuf *sb, struct conf **confs)
{
	return manio_read_with_blk(manio, sb, NULL, NULL, confs);
}

static int reset_sig_count_and_close(struct manio *manio)
{
	if(sort_and_write_hooks_and_dindex(manio)) return -1;
	if(fzp_close(&manio->fzp)) return -1;
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

int manio_write_sig_and_path(struct manio *manio, struct blk *blk)
{
	if(manio->protocol==PROTO_1) return 0;
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
				MSAVE_PATH_LEN+1, "%s", savepathstr);
		}
	}
	return write_sig_msg(manio, sig_to_msg(blk, 1 /* save_path */));
}

int manio_write_sbuf(struct manio *manio, struct sbuf *sb)
{
	if(!manio->fzp && manio_open_next_fpath(manio)) return -1;
	return sbuf_to_manifest(sb, manio->fzp);
}

// Return -1 on error, 0 on OK, 1 for srcmanio finished.
int manio_copy_entry(struct sbuf *csb, struct sbuf *sb,
	struct blk **blk, struct manio *srcmanio,
	struct manio *dstmanio, struct conf **confs)
{
	static int ars;
	static char *copy=NULL;

	// Use the most recent stat for the new manifest.
	if(dstmanio)
	{
		if(manio_write_sbuf(dstmanio, sb)) goto error;
		if(dstmanio->protocol==PROTO_1)
		{
			sbuf_free_content(csb);
			return 0;
		}
	}

	if(!(copy=strdup_w(csb->path.buf, __func__)))
		goto error;
	while(1)
	{
		if((ars=manio_read_with_blk(srcmanio, csb,
			*blk, NULL, confs))<0) goto error;
		else if(ars>0)
		{
			// Finished.
			sbuf_free_content(csb);
			blk_free(blk);
			free_w(&copy);
			return 1;
		}

		// Got something.
		if(strcmp(csb->path.buf, copy))
		{
			// Found the next entry.
			free_w(&copy);
			return 0;
		}
		if(dstmanio)
		{
			if(!dstmanio->fzp
			  && manio_open_next_fpath(dstmanio)) return -1;
			if(csb->endfile.buf)
			{
				if(iobuf_send_msg_fzp(&csb->endfile,
					dstmanio->fzp)) goto error;
			}
			else
			{
				// Should have the next signature.
				// Write it to the destination manifest.
				if(manio_write_sig_and_path(dstmanio, *blk))
					goto error;
			}
		}
	}

error:
	free_w(&copy);
	return -1;
}

int manio_forward_through_sigs(struct sbuf *csb, struct blk **blk,
	struct manio *manio, struct conf **confs)
{
	// Call manio_copy_entry with nothing to write to, so
	// that we forward through the sigs in manio.
	return manio_copy_entry(csb, NULL, blk, manio, NULL, confs);
}

man_off_t *manio_tell(struct manio *manio)
{
	man_off_t *offset=NULL;
	if(!manio->fzp)
	{
		logp("manio_tell called on null fzp\n");
		goto error;
	}
	if(!(offset=man_off_t_alloc())
	  || !(offset->fpath=strdup_w(manio->offset->fpath, __func__))
	  || (offset->offset=fzp_tell(manio->fzp))<0)
		goto error;
	offset->fcount=manio->offset->fcount;
	return offset;
error:
	man_off_t_free(&offset);
	return NULL;
}

int manio_seek(struct manio *manio, man_off_t *offset)
{
	fzp_close(&manio->fzp);
	if(!(manio->fzp=fzp_gzopen(offset->fpath, manio->mode))
	  || fzp_seek(manio->fzp, offset->offset, SEEK_SET))
		return -1;
	man_off_t_free_content(manio->offset);
	if(!(manio->offset->fpath=strdup_w(offset->fpath, __func__)))
		return -1;
	manio->offset->offset=offset->offset;
	manio->offset->fcount=offset->fcount;
	return 0;
}

static int remove_trailing_files(struct manio *manio, man_off_t *offset)
{
	int ret=-1;
	char *fpath=NULL;
	struct stat statp;
	while(1)
	{
		free_w(&fpath);
		if(!(fpath=get_next_fpath(manio, offset)))
			goto end;
		if(lstat(fpath, &statp)) break;
		if(!S_ISREG(statp.st_mode))
			goto end;
		if(recursive_delete(fpath))
			goto end;
	}
	ret=0;
end:
	free_w(&fpath);
	return ret;
}

int manio_truncate(struct manio *manio, man_off_t *offset, struct conf **confs)
{
	int ret=-1;
	errno=0;
	if(fzp_truncate(offset->fpath, FZP_FILE, offset->offset, confs))
	{
		logp("Could not fzp_truncate %s in %s(): %s\n",
			manio->manifest, __func__, strerror(errno));
		goto end;
	}
	if(!is_single_file(manio)
	  && remove_trailing_files(manio, offset))
		goto end;
	ret=0;
end:
	return ret;
}
