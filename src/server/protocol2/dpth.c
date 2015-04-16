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

#include <dirent.h>

static int get_data_lock(struct lock *lock, struct dpth *dpth, const char *path)
{
	int ret=-1;
	char *p=NULL;
	char *lockfile=NULL;
	// Use just the first three components, excluding sig number.
	if(!(p=prepend_slash(dpth->base_path, path, 14))
	  || !(lockfile=prepend(p, ".lock", strlen(".lock"), "")))
		goto end;
	if(lock_init(lock, lockfile)
	  || build_path_w(lock->path))
		goto end;
	lock_get_quick(lock);
	ret=0;
end:
	free_w(&p);
	free_w(&lockfile);
	return ret;
}

static char *dpth_mk_prim(struct dpth *dpth)
{
	static char path[8];
	snprintf(path, sizeof(path), "%04X", dpth->prim);
	return path;
}

static char *dpth_mk_seco(struct dpth *dpth)
{
	static char path[16];
	snprintf(path, sizeof(path), "%04X/%04X", dpth->prim, dpth->seco);
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
/*
printf("added: %s\n", dlnew->save_path);
printf("head: %s\n", dpth->head->save_path);
printf("tail: %s\n", dpth->tail->save_path);
*/
	return 0;
}

char *dpth_get_save_path(struct dpth *dpth)
{
	static char save_path[32];
	snprintf(save_path, sizeof(save_path), "%04X/%04X/%04X/%04X",
		dpth->prim, dpth->seco, dpth->tert, dpth->sig);
	return save_path;
}

char *dpth_mk(struct dpth *dpth)
{
	static char *save_path=NULL;
	static struct lock *lock=NULL;
	while(1)
	{
		save_path=dpth_get_save_path(dpth);
		if(!dpth->need_data_lock) return save_path;

		if(!lock && !(lock=lock_alloc())) goto error;
		if(get_data_lock(lock, dpth, save_path)) goto error;
		switch(lock->status)
		{
			case GET_LOCK_GOT: break;
			case GET_LOCK_NOT_GOT:
				// Increment and try again.
				if(dpth_incr(dpth)) goto error;
				continue;
			case GET_LOCK_ERROR:
			default:
				goto error;
		}

		dpth->need_data_lock=0; // Got it.
		if(add_lock_to_list(dpth, lock, save_path)) goto error;
		lock=NULL;
		return save_path;
	}
error:
	lock_free(&lock);
	return NULL;
}

// Returns 0 on OK, -1 on error. *max gets set to the next entry.
static int get_highest_entry(const char *path, int *max)
{
	int ent=0;
	int ret=0;
	DIR *d=NULL;
	FILE *ifp=NULL;
	struct dirent *dp=NULL;

	*max=-1;
	if(!(d=opendir(path))) goto end;
	while((dp=readdir(d)))
	{
		if(!dp->d_ino
		  || strlen(dp->d_name)!=4)
			continue;
		ent=strtol(dp->d_name, NULL, 16);
		if(ent>*max) *max=ent;
	}

end:
	if(d) closedir(d);
	close_fp(&ifp);
	return ret;
}

int dpth_incr_sig(struct dpth *dpth)
{
	if(++dpth->sig<DATA_FILE_SIG_MAX) return 0;
	dpth->sig=0;
	dpth->need_data_lock=1;
	return dpth_incr(dpth);
}

int dpth_init(struct dpth *dpth, const char *base_path,
	int max_storage_subdirs)
{
	int max;
	int ret=0;
	char *tmp=NULL;

	dpth->max_storage_subdirs=max_storage_subdirs;

	free_w(&dpth->base_path);
	if(!(dpth->base_path=strdup_w(base_path, __func__)))
		goto error;

	dpth->sig=0;
	dpth->need_data_lock=1;

	if(get_highest_entry(dpth->base_path, &max))
		goto error;
	if(max<0) max=0;
	dpth->prim=max;
	tmp=dpth_mk_prim(dpth);
	if(!(tmp=prepend_s(dpth->base_path, tmp)))
		goto error;

	if(get_highest_entry(tmp, &max))
		goto error;
	if(max<0) max=0;
	dpth->seco=max;
	free_w(&tmp);
	tmp=dpth_mk_seco(dpth);
	if(!(tmp=prepend_s(dpth->base_path, tmp)))
		goto error;

	if(get_highest_entry(tmp, &max))
		goto error;
	if(max<0)
	{
		dpth->tert=0;
	}
	else
	{
		dpth->tert=max;
		if(dpth_incr(dpth)) goto error;
	}

	goto end;
error:
	ret=-1;
end:
	free_w(&tmp);
	return ret;
}

static int fprint_tag(FILE *fp, enum cmd cmd, unsigned int s)
{
	if(fprintf(fp, "%c%04X", cmd, s)!=5)
	{
		logp("Short fprintf\n");
		return -1;
	}
	return 0;
}

static int fwrite_buf(enum cmd cmd, const char *buf, unsigned int s, FILE *fp)
{
	static size_t bytes;
	if(fprint_tag(fp, cmd, s)) return -1;
	if((bytes=fwrite(buf, 1, s, fp))!=s)
	{
		logp("Short write: %d\n", (int)bytes);
		return -1;
	}
	return 0;
}

static FILE *file_open_w(const char *path, const char *mode)
{
	FILE *fp;
	if(build_path_w(path)) return NULL;
	fp=open_file(path, "wb");
	return fp;
}

static FILE *open_data_file_for_write(struct dpth *dpth, struct blk *blk)
{
	FILE *fp=NULL;
	char *path=NULL;
	char *savepathstr=NULL;
	struct dpth_lock *head=dpth->head;
//printf("moving for: %s\n", blk->save_path);

	savepathstr=bytes_to_savepathstr(blk->savepath);

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
	fp=file_open_w(path, "wb");
end:
	free_w(&path);
	return fp;
}

int dpth_fwrite(struct dpth *dpth, struct iobuf *iobuf, struct blk *blk)
{
	//printf("want to write: %s\n", blk->save_path);

	// Remember that the save_path on the lock list is shorter than the
	// full save_path on the blk.
	if(dpth->fp
	  && strncmp(dpth->head->save_path,
		bytes_to_savepathstr(blk->savepath),
		sizeof(dpth->head->save_path)-1)
	  && dpth_release_and_move_to_next_in_list(dpth))
		return -1;

	// Open the current list head if we have no fp.
	if(!dpth->fp
	  && !(dpth->fp=open_data_file_for_write(dpth, blk))) return -1;

	return fwrite_buf(CMD_DATA, iobuf->buf, iobuf->len, dpth->fp);
}
