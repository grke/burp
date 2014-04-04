#include "include.h"

#include <dirent.h>

#define MAX_STORAGE_SUBDIRS	30000

// Three levels with 65535 entries each gives
// 65535^3 = 281,462,092,005,375 data entries
// recommend a filesystem with lots of inodes?
// Hmm, but ext3 only allows 32000 subdirs, although that many files are OK.
static int dpth_incr(struct dpth *dpth)
{
	if(dpth->tert++<0xFFFF) return 0;
	dpth->tert=0;
	if(dpth->seco++<MAX_STORAGE_SUBDIRS) return 0;
	dpth->seco=0;
	if(dpth->prim++<MAX_STORAGE_SUBDIRS) return 0;
	dpth->prim=0;
	logp("Could not find any free data file entries out of the 15000*%d*%d available!\n", MAX_STORAGE_SUBDIRS, MAX_STORAGE_SUBDIRS);
	logp("Recommend moving the client storage directory aside and starting again.\n");
	return -1;
}

static int get_data_lock(struct lock *lock, struct dpth *dpth, const char *path)
{
	int ret=0;
	char *p=NULL;
	char *lockfile=NULL;
	// Use just the first three components, excluding sig number.
	if(!(p=prepend_slash(dpth->base_path, path, 14))
	  || !(lockfile=prepend(p, ".lock", strlen(".lock"), "")))
		goto end;
	if(lock_init(lock, lockfile)
	  || build_path_w(lock->path))
	{
		ret=-1;
		goto end;
	}
	lock_get_quick(lock);
end:
	if(p) free(p);
	if(lockfile) free(lockfile);
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
        if(!(dpth_lock=(struct dpth_lock *)calloc(1, sizeof(struct dpth_lock))))
	{
        	log_out_of_memory(__FUNCTION__);
		return NULL;
	}
	snprintf(dpth_lock->save_path, sizeof(dpth_lock->save_path),
		"%s", save_path);
        return dpth_lock;
}

static void dpth_lock_free(struct dpth_lock *dpth_lock)
{
	if(!dpth_lock) return;
	free(dpth_lock);
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

char *dpth_mk(struct dpth *dpth)
{
	static char save_path[32];
	static struct lock *lock=NULL;
	while(1)
	{
		snprintf(save_path, sizeof(save_path), "%04X/%04X/%04X/%04X",
			dpth->prim, dpth->seco, dpth->tert, dpth->sig);
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
static int get_highest_entry(const char *path, int *max, struct dpth *dpth)
{
	int ent=0;
	int ret=0;
	DIR *d=NULL;
	char *tmp=NULL;
	struct dirent *dp=NULL;
	FILE *ifp=NULL;

	*max=-1;
	if(!(d=opendir(path))) goto end;
	while((dp=readdir(d)))
	{
		if(dp->d_ino==0
		  || !strcmp(dp->d_name, ".")
		  || !strcmp(dp->d_name, ".."))
			continue;
		ent=strtol(dp->d_name, NULL, 16);
		if(ent>*max) *max=ent;
	}

end:
	if(d) closedir(d);
	if(ifp) fclose(ifp);
	if(tmp) free(tmp);
	return ret;
}

static int get_next_entry(const char *path, int *max, struct dpth *dpth)
{
	if(get_highest_entry(path, max, dpth)) return -1;
	(*max)++;
	return 0;
}

struct dpth *dpth_alloc(const char *base_path)
{
        struct dpth *dpth=NULL;
        if((dpth=(struct dpth *)calloc(1, sizeof(struct dpth)))
	  && (dpth->base_path=strdup(base_path)))
		return dpth;
	log_out_of_memory(__FUNCTION__);
	dpth_free(dpth);
	return NULL;
}

int dpth_incr_sig(struct dpth *dpth)
{
	if(++dpth->sig<DATA_FILE_SIG_MAX) return 0;
	dpth->sig=0;
	dpth->need_data_lock=1;
	return dpth_incr(dpth);
}

int dpth_init(struct dpth *dpth)
{
	int max;
	int ret=0;
	char *tmp=NULL;

	if(get_highest_entry(dpth->base_path, &max, NULL))
		goto error;
	if(max<0) max=0;
	dpth->prim=max;
	tmp=dpth_mk_prim(dpth);
	if(!(tmp=prepend_s(dpth->base_path, tmp)))
		goto error;

	if(get_highest_entry(tmp, &max, NULL))
		goto error;
	if(max<0) max=0;
	dpth->seco=max;
	free(tmp);
	tmp=dpth_mk_seco(dpth);
	if(!(tmp=prepend_s(dpth->base_path, tmp)))
		goto error;

	if(get_next_entry(tmp, &max, dpth))
		goto error;
	if(max<0) max=0;
	dpth->tert=max;

	dpth->sig=0;
	dpth->need_data_lock=1;

	goto end;
error:
	ret=-1;
end:
	if(tmp) free(tmp);
	return ret;
}

void dpth_free(struct dpth *dpth)
{
	if(!dpth) return;
	if(dpth->base_path) free(dpth->base_path);
	free(dpth);
	dpth=NULL;
}

static int fprint_tag(FILE *fp, char cmd, unsigned int s)
{
	if(fprintf(fp, "%c%04X", cmd, s)!=5)
	{
		logp("Short fprintf\n");
		return -1;
	}
	return 0;
}

static int fwrite_buf(char cmd, const char *buf, unsigned int s, FILE *fp)
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

static int release_and_move_to_next_in_list(struct dpth *dpth)
{
	int ret=0;
	struct dpth_lock *next=NULL;

	// Try to release (and unlink) the lock even if close_fp failed, just
	// to be tidy.
	if(close_fp(&dpth->fp)) ret=-1;
	if(lock_release(dpth->head->lock)) ret=-1;
	lock_free(&dpth->head->lock);

	next=dpth->head->next;
	if(dpth->head==dpth->tail) dpth->tail=next;
	dpth_lock_free(dpth->head);
	dpth->head=next;
	return ret;
}

static FILE *open_data_file_for_write(struct dpth *dpth, struct blk *blk)
{
	FILE *fp=NULL;
	char *path=NULL;
	struct dpth_lock *head=dpth->head;
//printf("moving for: %s\n", blk->save_path);

	// Sanity check. They should be coming through from the client
	// in the same order in which we locked them.
	// Remember that the save_path on the lock list is shorter than the
	// full save_path on the blk.
	if(!head
	  || strncmp(head->save_path, blk->save_path, sizeof(head->save_path)-1))
	{
		logp("lock and block save_path mismatch: %s %s\n",
			head?head->save_path:"(null)", blk->save_path);
		printf("lock and block save_path mismatch: %s %s\n",
			head?head->save_path:"(null)", blk->save_path);
		goto end;
	}

	if(!(path=prepend_slash(dpth->base_path, blk->save_path, 14)))
		goto end;
	fp=file_open_w(path, "wb");
end:
	if(path) free(path);
	return fp;
}

int dpth_fwrite(struct dpth *dpth, struct iobuf *iobuf, struct blk *blk)
{
	//printf("want to write: %s\n", blk->save_path);

	// Remember that the save_path on the lock list is shorter than the
	// full save_path on the blk.
	if(dpth->fp
	  && strncmp(dpth->head->save_path,
		blk->save_path, sizeof(dpth->head->save_path)-1)
	  && release_and_move_to_next_in_list(dpth))
		return -1;

	// Open the current list head if we have no fp.
	if(!dpth->fp
	  && !(dpth->fp=open_data_file_for_write(dpth, blk))) return -1;

	return fwrite_buf(CMD_DATA, iobuf->buf, iobuf->len, dpth->fp);
}

int dpth_release_all(struct dpth *dpth)
{
	int ret=0;
	if(!dpth) return 0;
	if(dpth->fp && close_fp(&dpth->fp)) ret=-1;
	while(dpth->head) if(release_and_move_to_next_in_list(dpth)) ret=-1;
	return ret;
}
