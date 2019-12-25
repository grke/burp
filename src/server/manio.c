#include "../burp.h"
#include "../alloc.h"
#include "../cmd.h"
#include "../fsops.h"
#include "../fzp.h"
#include "../hexmap.h"
#include "../log.h"
#include "../msg.h"
#include "../prepend.h"
#include "../protocol2/blk.h"
#include "../sbuf.h"
#include "manio.h"
#include "protocol2/champ_chooser/champ_chooser.h"
#include "protocol2/dpth.h"

static void man_off_t_free_content(man_off_t *offset)
{
	if(!offset) return;
	free_w(&offset->fpath);
	free_w(&offset->ppath);
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
	if(!(manio->hook_dir=strdup_w(hook_dir, __func__))
	  || !(manio->rmanifest=strdup_w(rmanifest, __func__))
	  || !(manio->hook_sort=(uint64_t *)calloc_w(MANIFEST_SIG_MAX,
		sizeof(uint64_t), __func__)))
			return -1;
	return 0;
}

static int init_write_dindex(struct manio *manio, const char *dir)
{
	if(!(manio->dindex_dir=strdup_w(dir, __func__))
	  || !(manio->dindex_sort=(uint64_t *)calloc_w(MANIFEST_SIG_MAX,
		sizeof(uint64_t), __func__)))
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
	snprintf(tmp, sizeof(tmp), "%08" PRIX64, offset->fcount++);
	return prepend_s(manio->manifest, tmp);
}

static int manio_open_next_fpath(struct manio *manio)
{
	static struct stat statp;
	man_off_t *offset=manio->offset;

	free_w(&offset->ppath);
	offset->ppath=offset->fpath;
	if(!(offset->fpath=get_next_fpath(manio, offset)))
		return -1;

	if(!strcmp(manio->mode, MANIO_MODE_READ)
	  && lstat(offset->fpath, &statp))
		return 0;

	if(build_path_w(offset->fpath))
		return -1;
	switch(manio->phase)
	{
		case 2:
			if(!(manio->fzp=fzp_open(offset->fpath,
				manio->mode))) return -1;
			return 0;
		case 1:
		case 3:
		default:
			if(!(manio->fzp=fzp_gzopen(offset->fpath,
				manio->mode))) return -1;
			return 0;
	}
}

static int manio_open_last_fpath(struct manio *manio)
{
	int max=-1;
	if(is_single_file(manio))
		return manio_open_next_fpath(manio);
	if(get_highest_entry(manio->manifest, &max, 8))
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
			logp("%s has phase: %d\n",
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
	free_w(&manio->rmanifest);
	free_w(&manio->hook_dir);
	free_v((void **)&manio->hook_sort);
	free_w(&manio->dindex_dir);
	free_v((void **)&manio->dindex_sort);
	memset(manio, 0, sizeof(struct manio));
}

#ifndef UTEST
static
#endif
int write_hook_header(struct fzp *fzp, const char *rmanifest, const char *msg)
{
	int ret=0;
	char *tmp=NULL;
	if(!(tmp=prepend_s(rmanifest, msg))
	  || send_msg_fzp(fzp, CMD_MANIFEST, tmp, strlen(tmp)))
		ret=-1;
	free_w(&tmp);
	return ret;
}

static int uint64_t_sort(const void *a, const void *b)
{
	uint64_t *x=(uint64_t *)a;
	uint64_t *y=(uint64_t *)b;
	if(*x>*y) return 1;
	if(*x<*y) return -1;
	return 0;
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
	if(fzp_printf(fzp, "%08" PRIX64 "\n", manio->offset->fcount)!=9)
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
		logp("data in %s is not the right length (%lu!=9)\n", path,
			(unsigned long)s);
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
	char msg[32]="";
	char *path=NULL;
	int hook_count=manio->hook_count;
	uint64_t *hook_sort=manio->hook_sort;
	if(!hook_sort) return 0;

	snprintf(msg, sizeof(msg), "%08" PRIX64, manio->offset->fcount-1);
	if(!(path=prepend_s(manio->hook_dir, msg))
	  || build_path_w(path)
	  || !(fzp=fzp_gzopen(path, MANIO_MODE_WRITE)))
		goto end;

	qsort(hook_sort, hook_count, sizeof(uint64_t), uint64_t_sort);

	if(write_hook_header(fzp, manio->rmanifest, msg)) goto end;
	for(i=0; i<hook_count; i++)
	{
		// Do not bother with duplicates.
		if(i && hook_sort[i]==hook_sort[i-1])
			continue;

		if(to_fzp_fingerprint(fzp, hook_sort[i]))
			goto end;
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
	char msg[32]="";
	char *path=NULL;
	struct iobuf wbuf;
	struct blk blk;
	int dindex_count=manio->dindex_count;
	uint64_t *dindex_sort=manio->dindex_sort;
	if(!dindex_sort) return 0;

	snprintf(msg, sizeof(msg), "%08" PRIX64, manio->offset->fcount-1);
	if(!(path=prepend_s(manio->dindex_dir, msg))
	  || build_path_w(path)
	  || !(fzp=fzp_gzopen(path, MANIO_MODE_WRITE)))
		goto end;

	qsort(dindex_sort, dindex_count, sizeof(uint64_t), uint64_t_sort);

	for(i=0; i<dindex_count; i++)
	{
		// Do not bother with duplicates.
		if(i && dindex_sort[i]==dindex_sort[i-1])
			continue;

		blk.savepath=dindex_sort[i];
		blk_to_iobuf_savepath(&blk, &wbuf);
		if(iobuf_send_msg_fzp(&wbuf, fzp)) return -1;
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
//	int fd;
	if(!manio || !*manio) return ret;
	if(sort_and_write_hooks_and_dindex(*manio))
		ret=-1;
/*
	There is no gzfileno()
	if((fd=fzp_fileno((*manio)->fzp))<0)
	{
		logp("Could not get fileno in %s for %s: %s\n", __func__,
			(*manio)->manifest, strerror(errno));
		ret=-1;
	}
	// Should probably have a flush before fsync too.
	if(fsync(fd))
	{
		logp("Error in fsync in %s for %s: %s\n", __func__,
			(*manio)->manifest, strerror(errno));
		ret=-1;
	}
*/
	if(fzp_close(&((*manio)->fzp)))
		ret=-1;
	sync();
	manio_free_content(*manio);
	free_v((void **)manio);
	return ret;
}

// Return -1 for error, 0 for stuff read OK, 1 for end of files.
int manio_read_with_blk(struct manio *manio, struct sbuf *sb, struct blk *blk)
{
	while(1)
	{
		if(!manio->fzp)
		{
			if(manio_open_next_fpath(manio)) goto error;
			if(!manio->fzp) return 1; // No more files to read.
		}

		switch(sbuf_fill_from_file(sb, manio->fzp, blk))
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

int manio_read(struct manio *manio, struct sbuf *sb)
{
	return manio_read_with_blk(manio, sb, NULL);
}

static int reset_sig_count_and_close(struct manio *manio)
{
	if(sort_and_write_hooks_and_dindex(manio)) return -1;
	if(fzp_close(&manio->fzp)) return -1;
	manio->sig_count=0;
	if(manio_open_next_fpath(manio)) return -1;
	return 0;
}

#ifndef UTEST
static
#endif
int manio_find_boundary(uint8_t *md5sum)
{
	int i;
	uint8_t x;
	uint8_t y;
	uint8_t b4=0;

	// I am currently making it look for four of the same consecutive
	// characters in the md5sum.
	for(i=0; i<MD5_DIGEST_LENGTH-1; i++)
	{
		x=md5sum[i]>>4;
		y=md5sum[i]&0x0F;
		if(x==y)
		{
			if(x!=md5sum[i+1]>>4)
				continue;
			if(i && x==b4)
				return 1;
			if(x==(md5sum[i+1]&0x0F))
				return 1;
		}
		b4=y;
	}
	return 0;
}

// After conditions are met, close the file currently being written to.
// Allow the number of signatures to be vary between MANIFEST_SIG_MIN and
// MANIFEST_SIG_MAX. This will hopefully allow fewer candidate manifests
// generated, since the boundary will be able to vary.
static int check_sig_count(struct manio *manio, struct blk *blk)
{
	manio->sig_count++;

	if(manio->sig_count<MANIFEST_SIG_MIN)
		return 0; // Not yet time to close.

	if(manio->sig_count>=MANIFEST_SIG_MAX)
		return reset_sig_count_and_close(manio); // Time to close.

	// At this point, dynamically decide based on the current msg.
	if(manio_find_boundary(blk->md5sum))
		return reset_sig_count_and_close(manio); // Time to close.
	return 0;
}

static int write_sig_msg(struct manio *manio, struct blk *blk)
{
	struct iobuf wbuf;
	if(!manio->fzp && manio_open_next_fpath(manio)) return -1;
	blk_to_iobuf_sig_and_savepath(blk, &wbuf);
	if(iobuf_send_msg_fzp(&wbuf, manio->fzp)) return -1;
	return check_sig_count(manio, blk);
}

int manio_write_sig_and_path(struct manio *manio, struct blk *blk)
{
	if(manio->protocol==PROTO_1) return 0;
	if(manio->hook_sort && blk_fingerprint_is_hook(blk))
	{
		// Add to list of hooks for this manifest chunk.
		manio->hook_sort[manio->hook_count++]=blk->fingerprint;
	}
	if(manio->dindex_sort)
	{
		uint64_t savepath=blk->savepath;
		savepath &= 0xFFFFFFFFFFFF0000ULL;
		// Ignore obvious duplicates.
		if(!manio->dindex_count
		  || manio->dindex_sort[manio->dindex_count-1]!=savepath)
		{
			// Add to list of dindexes for this manifest chunk.
			manio->dindex_sort[manio->dindex_count++]=savepath;
		}
	}
	return write_sig_msg(manio, blk);
}

int manio_write_sbuf(struct manio *manio, struct sbuf *sb)
{
	if(!manio->fzp && manio_open_next_fpath(manio)) return -1;
	return sbuf_to_manifest(sb, manio->fzp);
}

int manio_write_cntr(struct manio *manio, struct sbuf *sb,
	enum cntr_manio what)
{
	if(!manio->fzp && manio_open_next_fpath(manio)) return -1;
	return sbuf_to_manifest_cntr(sb, manio->fzp, what);
}

// Return -1 on error, 0 on OK, 1 for srcmanio finished.
int manio_copy_entry(struct sbuf *csb, struct sbuf *sb,
	struct manio *srcmanio, struct manio *dstmanio,
	const char *seed_src, const char *seed_dst)
{
	int ars;
	struct iobuf copy1;
	struct iobuf copy2;
	struct blk *blk;
	memset(&copy1, 0, sizeof(copy1));
	memset(&copy2, 0, sizeof(copy2));
	if(!(blk=blk_alloc()))
		goto error;

	// Use the most recent stat for the new manifest.
	if(dstmanio)
	{
		int e=0;
		struct iobuf save1;
		struct iobuf save2;
		memset(&save1, 0, sizeof(save1));
		memset(&save2, 0, sizeof(save2));
	
		// When seeding, adjust the prefixes, but we need to remember
		// the original too.
		if(seed_src && seed_dst)
		{
			char *tmp=sb->path.buf+strlen(seed_src);
			if(!(copy1.buf=strdup_w(seed_dst, __func__)))
				goto error;
			if(astrcat(&copy1.buf, "/", __func__))
				goto error;
			if(*tmp=='/')
				tmp++;
			if(astrcat(&copy1.buf, tmp, __func__))
				goto error;
			copy1.len=strlen(copy1.buf);
			copy1.cmd=sb->path.cmd;

			if(sb->protocol1 && sb->protocol1->datapth.buf
			  && !strncmp(sb->protocol1->datapth.buf,
				TREE_DIR, strlen(TREE_DIR)))
			{
				tmp=sb->protocol1->datapth.buf
					+strlen(TREE_DIR)
					+strlen(seed_src);
				if(*tmp=='/')
					tmp++;
				if(!(copy2.buf=strdup_w(TREE_DIR, __func__)))
					goto error;
				if(*seed_dst!='/'
				  && astrcat(&copy2.buf, "/", __func__))
					goto error;
				if(astrcat(&copy2.buf, seed_dst, __func__)
				  || astrcat(&copy2.buf, "/", __func__)
				  || astrcat(&copy2.buf, tmp, __func__))
					goto error;
				copy2.len=strlen(copy2.buf);
				copy2.cmd=sb->protocol1->datapth.cmd;
			}

			save1=sb->path;
			sb->path=copy1;

			if(copy2.buf)
			{
				save2=sb->protocol1->datapth;
				sb->protocol1->datapth=copy2;
			}
		}
		e=manio_write_sbuf(dstmanio, sb);
		if(copy1.buf)
		{
			sb->path=save1;
			iobuf_free_content(&copy1);
		}
		if(copy2.buf)
		{
			sb->protocol1->datapth=save2;
			iobuf_free_content(&copy2);
		}
		if(e)
			goto error;

		if(dstmanio->protocol==PROTO_1)
		{
			sbuf_free_content(csb);
			blk_free(&blk);
			return 0;
		}
	}

	copy1.len=csb->path.len;
	copy1.cmd=csb->path.cmd;
	if(!(copy1.buf=strdup_w(csb->path.buf, __func__)))
		goto error;
	while(1)
	{
		if((ars=manio_read_with_blk(srcmanio, csb, blk))<0)
			goto error;
		else if(ars>0)
		{
			// Finished.
			sbuf_free_content(csb);
			blk_free(&blk);
			iobuf_free_content(&copy1);
			return 1;
		}

		// Got something.
		if(iobuf_pathcmp(&csb->path, &copy1))
		{
			// Found the next entry.
			iobuf_free_content(&copy1);
			blk_free(&blk);
			return 0;
		}
		if(dstmanio)
		{
			if(!dstmanio->fzp
			  && manio_open_next_fpath(dstmanio))
				goto error;

			if(csb->endfile.buf)
			{
				if(iobuf_send_msg_fzp(&csb->endfile,
					dstmanio->fzp)) goto error;
			}
			else
			{
				// Should have the next signature.
				// Write it to the destination manifest.
				if(manio_write_sig_and_path(dstmanio, blk))
					goto error;
			}
		}
	}

error:
	blk_free(&blk);
	iobuf_free_content(&copy1);
	iobuf_free_content(&copy2);
	return -1;
}

int manio_forward_through_sigs(struct sbuf *csb, struct manio *manio)
{
	// Call manio_copy_entry with nothing to write to, so
	// that we forward through the sigs in manio.
	return manio_copy_entry(csb, NULL, manio, NULL, NULL, NULL);
}

man_off_t *manio_tell(struct manio *manio)
{
	man_off_t *offset=NULL;
	if(!manio->fzp)
	{
		logp("%s called on null fzp\n", __func__);
		if(manio->offset && manio->offset->fpath)
			logp("manio->offset->fpath: %s\n",
				manio->offset->fpath);
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

int manio_close_and_truncate(struct manio **manio,
	man_off_t *offset, int compression)
{
	int ret=-1;
	errno=0;
	if(!is_single_file(*manio)
	  && remove_trailing_files(*manio, offset))
		goto end;
	if(manio_close(manio)) goto end;
	if(fzp_truncate(offset->fpath, FZP_FILE, offset->offset, compression))
	{
		logp("Could not fzp_truncate %s in %s(): %s\n",
			offset->fpath, __func__, strerror(errno));
		goto end;
	}
	ret=0;
end:
	return ret;
}
