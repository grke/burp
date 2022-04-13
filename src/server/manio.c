#include "../burp.h"
#include "../alloc.h"
#include "../cmd.h"
#include "../fsops.h"
#include "../fzp.h"
#include "../hexmap.h"
#include "../log.h"
#include "../msg.h"
#include "../prepend.h"
#include "../sbuf.h"
#include "manio.h"

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

static char *get_next_fpath(struct manio *manio, man_off_t *offset)
{
	return strdup_w(manio->manifest, __func__);
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
	return manio_open_next_fpath(manio);
}

static struct manio *manio_alloc(void)
{
	return (struct manio *)calloc_w(1, sizeof(struct manio), __func__);
}

static struct manio *do_manio_open(const char *manifest, const char *mode,
	int phase)
{
	struct manio *manio=NULL;
	if(!(manio=manio_alloc())
	  || !(manio->manifest=strdup_w(manifest, __func__))
	  || !(manio->mode=strdup_w(mode, __func__))
	  || !(manio->offset=man_off_t_alloc()))
		goto error;
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

struct manio *manio_open(const char *manifest, const char *mode)
{
	return do_manio_open(manifest, mode, 0);
}

struct manio *manio_open_phase1(const char *manifest, const char *mode)
{
	return do_manio_open(manifest, mode, 1);
}

struct manio *manio_open_phase2(const char *manifest, const char *mode)
{
	return do_manio_open(manifest, mode, 2);
}

struct manio *manio_open_phase3(const char *manifest, const char *mode,
	const char *rmanifest)
{
	return do_manio_open(manifest, mode, 3);
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

static char *get_fcount_path(struct manio *manio)
{
	return prepend_s(manio->manifest, "fcount");
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

int manio_close(struct manio **manio)
{
	int ret=0;
//	int fd;
	if(!manio || !*manio) return ret;
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
int manio_read(struct manio *manio, struct sbuf *sb)
{
	while(1)
	{
		if(!manio->fzp)
		{
			if(manio_open_next_fpath(manio)) goto error;
			if(!manio->fzp) return 1; // No more files to read.
		}

		switch(sbuf_fill_from_file(sb, manio->fzp))
		{
			case 0: return 0; // Got something.
			case 1: break; // Keep going.
			default: goto error; // Error.
		}

		// Reached the end of the current file.
		// Maybe there is another file to continue with.
		if(fzp_close(&manio->fzp)) goto error;
		return 1;
	}

error:
	return -1;
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
	memset(&copy1, 0, sizeof(copy1));
	memset(&copy2, 0, sizeof(copy2));

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

			if(sb->protocol1->datapth.buf
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

		sbuf_free_content(csb);
		return 0;
	}

	copy1.len=csb->path.len;
	copy1.cmd=csb->path.cmd;
	if(!(copy1.buf=strdup_w(csb->path.buf, __func__)))
		goto error;
	while(1)
	{
		if((ars=manio_read(srcmanio, csb))<0)
			goto error;
		else if(ars>0)
		{
			// Finished.
			sbuf_free_content(csb);
			iobuf_free_content(&copy1);
			return 1;
		}

		// Got something.
		if(iobuf_pathcmp(&csb->path, &copy1))
		{
			// Found the next entry.
			iobuf_free_content(&copy1);
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
		}
	}

error:
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

int manio_close_and_truncate(struct manio **manio,
	man_off_t *offset, int compression)
{
	int ret=-1;
	errno=0;
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
