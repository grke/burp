#include "../../burp.h"
#include "../../alloc.h"
#include "../../cmd.h"
#include "../../fsops.h"
#include "../../hexmap.h"
#include "../../iobuf.h"
#include "../../lock.h"
#include "../../log.h"
#include "../../prepend.h"
#include "../../protocol2/blk.h"
#include "dpth.h"

static int get_data_lock(struct lock *lock, const char *path)
{
	int ret=-1;
	char *lockfile=NULL;
	// Use just the first three components, excluding sig number.
	if(!(lockfile=prepend(path, ".lock")))
		goto end;
	if(lock_init(lock, lockfile)
	  || build_path_w(lock->path))
		goto end;
	lock_get_quick(lock);
	ret=0;
end:
	free_w(&lockfile);
	return ret;
}

static char *dpth_mk_prim(struct dpth *dpth)
{
	static char path[8];
	snprintf(path, sizeof(path), "%04X", dpth->comp[0]);
	return path;
}

static char *dpth_mk_seco(struct dpth *dpth)
{
	static char path[16];
	snprintf(path, sizeof(path), "%04X/%04X", dpth->comp[0], dpth->comp[1]);
	return path;
}

static struct dpth_lock *dpth_lock_alloc(const char *save_path)
{
        struct dpth_lock *dpth_lock;
        if(!(dpth_lock=(struct dpth_lock *)
		calloc_w(1, sizeof(struct dpth_lock), __func__)))
			return NULL;
	snprintf(dpth_lock->save_path, sizeof(dpth_lock->save_path),
		"%s", save_path);
        return dpth_lock;
}

static int add_lock_to_list(struct dpth *dpth,
	struct lock *lock, const char *save_path)
{
	struct dpth_lock *dlnew;
	if(!(dlnew=dpth_lock_alloc(save_path))) return -1;
	dlnew->lock=lock;

	// Add to the end of the list.
	if(dpth->tail) dpth->tail->next=dlnew;
	else if(!dpth->head) dpth->head=dlnew;
	dpth->tail=dlnew;
	return 0;
}

char *dpth_protocol2_get_save_path(struct dpth *dpth)
{
	static char save_path[32];
	snprintf(save_path, sizeof(save_path), "%04X/%04X/%04X/%04X",
		dpth->comp[0], dpth->comp[1], dpth->comp[2], dpth->comp[3]);
	return save_path;
}

char *dpth_protocol2_mk(struct dpth *dpth)
{
	char *p=NULL;
	static char *save_path=NULL;
	static struct lock *lock=NULL;
	struct stat statp;

	while(1)
	{
		free_w(&p);
		save_path=dpth_protocol2_get_save_path(dpth);
		if(!dpth->need_data_lock)
			return save_path;

		if(!lock && !(lock=lock_alloc()))
			goto error;

		// Use just the first three components, excluding sig number.
		if(!(p=prepend_slash(dpth->base_path, save_path, 14)))
			goto error;

		if(get_data_lock(lock, p))
			goto error;

		switch(lock->status)
		{
			case GET_LOCK_GOT:
				if(lstat(p, &statp))
				{
					// File does not exist yet, and we
					// have the lock. All good.
					break;
				}
				// The file that we want to write already
				// exists.
				if(lock_release(lock))
					goto error;
				lock_free(&lock);
				// Fall through and try again.
			case GET_LOCK_NOT_GOT:
				// Increment and try again.
				if(dpth_incr(dpth))
					goto error;
				continue;
			case GET_LOCK_ERROR:
			default:
				goto error;
		}

		dpth->need_data_lock=0; // Got it.
		if(add_lock_to_list(dpth, lock, save_path))
			goto error;
		lock=NULL;
		free_w(&p);
		return save_path;
	}
error:
	free_w(&p);
	lock_free(&lock);
	return NULL;
}

// Returns 0 on OK, -1 on error. *max gets set to the next entry.
int get_highest_entry(const char *path, int *max, size_t len)
{
	int ent=0;
	int ret=0;
	DIR *d=NULL;
	struct dirent *dp=NULL;

	*max=-1;
	if(!(d=opendir(path))) goto end;
	while((dp=readdir(d)))
	{
		if(!dp->d_ino
		  || strlen(dp->d_name)!=len)
			continue;
		ent=strtol(dp->d_name, NULL, 16);
		if(ent>*max) *max=ent;
	}

end:
	if(d) closedir(d);
	return ret;
}

int dpth_protocol2_incr_sig(struct dpth *dpth)
{
	if(++dpth->comp[3]<DATA_FILE_SIG_MAX) return 0;
	dpth->comp[3]=0;
	dpth->need_data_lock=1;
	return dpth_incr(dpth);
}

static int open_cfile_fzp(struct dpth *dpth,
	const char *cname, const char *cfiles)
{
	int fd;
	int ret=-1;
	char *fname=NULL;
	char *fullpath=NULL;

	if(!(fname=prepend(cname, "XXXXXX")))
		goto end;
	if(!(fullpath=prepend_s(cfiles, fname)))
		goto end;
	errno=0;
	if(build_path_w(fullpath) && errno!=EEXIST)
		goto end;
	if((fd=mkstemp(fullpath))<0)
	{
		logp("Could not mkstemp from template %s: %s\n",
			fullpath, strerror(errno));
		goto end;
	}
	if(!(dpth->cfile_fzp=fzp_dopen(fd, "wb")))
		goto end;

	ret=0;
end:
	free_w(&fname);
	free_w(&fullpath);
	return ret;
}

int dpth_protocol2_init(struct dpth *dpth, const char *base_path,
	const char *cname, const char *cfiles, int max_storage_subdirs)
{
	int max;
	int ret=0;
	char *tmp=NULL;

	if(!base_path)
	{
		logp("No base_path supplied in %s()\n", __func__);
		goto error;
	}

	if(open_cfile_fzp(dpth, cname, cfiles)) goto error;

	dpth->max_storage_subdirs=max_storage_subdirs;

	free_w(&dpth->base_path);
	if(!(dpth->base_path=strdup_w(base_path, __func__)))
		goto error;

	dpth->savepath=0;
	dpth->need_data_lock=1;

	if(get_highest_entry(dpth->base_path, &max, 4))
		goto error;
	if(max<0) max=0;
	dpth->comp[0]=max;
	tmp=dpth_mk_prim(dpth);
	if(!(tmp=prepend_s(dpth->base_path, tmp)))
		goto error;

	if(get_highest_entry(tmp, &max, 4))
		goto error;
	if(max<0) max=0;
	dpth->comp[1]=max;
	free_w(&tmp);
	tmp=dpth_mk_seco(dpth);
	if(!(tmp=prepend_s(dpth->base_path, tmp)))
		goto error;

	if(get_highest_entry(tmp, &max, 4))
		goto error;
	if(max<0)
	{
		dpth->comp[2]=0;
	}
	else
	{
		dpth->comp[2]=max;
		if(dpth_incr(dpth)) goto error;
	}

	goto end;
error:
	ret=-1;
end:
	free_w(&tmp);
	return ret;
}

static int fprint_tag(struct fzp *fzp, enum cmd cmd, unsigned int s)
{
	if(fzp_printf(fzp, "%c%04X", cmd, s)!=5)
	{
		logp("Short fprintf\n");
		return -1;
	}
	return 0;
}

static int fwrite_buf(enum cmd cmd,
	const char *buf, unsigned int s, struct fzp *fzp)
{
	static size_t bytes;
	if(fprint_tag(fzp, cmd, s)) return -1;
	if((bytes=fzp_write(fzp, buf, s))!=s)
	{
		logp("Short write: %d\n", (int)bytes);
		return -1;
	}
	return 0;
}

static struct fzp *file_open_w(const char *path)
{
	if(build_path_w(path)) return NULL;
	return fzp_open(path, "wb");
}

static int write_to_cfile(struct dpth *dpth, struct blk *blk)
{
	struct iobuf wbuf;
	blk_to_iobuf_savepath(blk, &wbuf);
	if(iobuf_send_msg_fzp(&wbuf, dpth->cfile_fzp))
		return -1;
	if(fzp_flush(dpth->cfile_fzp))
		return -1;
	if(fsync(fzp_fileno(dpth->cfile_fzp)))
	{
		logp("fsync on cfile_fzp failed: %s\n", strerror(errno));
		return -1;
	}
	return 0;
}

static struct fzp *open_data_file_for_write(struct dpth *dpth, struct blk *blk)
{
	char *path=NULL;
	struct fzp *fzp=NULL;
	char *savepathstr=NULL;
	struct dpth_lock *head=dpth->head;

	savepathstr=uint64_to_savepathstr(blk->savepath);

	// Sanity check. They should be coming through from the client
	// in the same order in which we locked them.
	// Remember that the save_path on the lock list is shorter than the
	// full save_path on the blk.
	if(!head
	  || strncmp(head->save_path,
		//FIX THIS
		savepathstr, sizeof(head->save_path)-1))
	{
		logp("lock and block save_path mismatch: %s %s\n",
			head?head->save_path:"(null)", savepathstr);
		goto end;
	}

	if(!(path=prepend_slash(dpth->base_path, savepathstr, 14)))
		goto end;
	if(write_to_cfile(dpth, blk))
		goto end;
	fzp=file_open_w(path);
end:
	free_w(&path);
	return fzp;
}

int dpth_protocol2_fwrite(struct dpth *dpth,
	struct iobuf *iobuf, struct blk *blk)
{
	// Remember that the save_path on the lock list is shorter than the
	// full save_path on the blk.
	if(dpth->fzp
	  && strncmp(dpth->head->save_path,
		uint64_to_savepathstr(blk->savepath),
		sizeof(dpth->head->save_path)-1)
	  && dpth_release_and_move_to_next_in_list(dpth))
		return -1;

	// Open the current list head if we have no fzp.
	if(!dpth->fzp
	  && !(dpth->fzp=open_data_file_for_write(dpth, blk))) return -1;

	return fwrite_buf(CMD_DATA, iobuf->buf, iobuf->len, dpth->fzp);
}
