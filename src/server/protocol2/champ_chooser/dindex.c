#include "../../../burp.h"
#include "../../../alloc.h"
#include "../../../fsops.h"
#include "../../../hexmap.h"
#include "../../../lock.h"
#include "../../../log.h"
#include "../../../prepend.h"
#include "../../../protocol2/blk.h"
#include "../../../sbuf.h"
#include "../../../strlist.h"
#include "../../sdirs.h"
#include "../backup_phase4.h"
#include "dindex.h"

static int backup_in_progress(const char *fullpath)
{
	int ret=-1;
	struct stat statp;
	char *working=NULL;
	char *finishing=NULL;
	char *dfiles_regenerating=NULL;

	if(!(working=prepend_s(fullpath, "working"))
	  || !(finishing=prepend_s(fullpath, "finishing"))
	  || !(dfiles_regenerating=prepend_s(fullpath, "dfiles.regenerating")))
		goto end;

	if(!lstat(working, &statp)
	  || !lstat(finishing, &statp))
	{
		logp("%s looks like it has a backup in progress.\n",
			fullpath);
		ret=1;
		goto end;
	}
	if(!lstat(dfiles_regenerating, &statp))
	{
		logp("%s looks like it was interrupted whilst "
			"regenerating its dfiles.\n", fullpath);
		ret=1;
		goto end;
	}
	ret=0;
end:
	if(ret==1)
		logp("Give up clean up attempt.\n");
	free_w(&working);
	free_w(&finishing);
	free_w(&dfiles_regenerating);
	return ret;
}

// Returns 0 on OK, -1 on error, 1 if there were backups already in progress.
static int get_dfiles_to_merge(struct sdirs *sdirs, struct strlist **s)
{
	int i=0;
	int n=0;
	int ret=-1;
	struct stat statp;
	char *fullpath=NULL;
	char *dfiles=NULL;
	struct dirent **dir=NULL;

	if((n=scandir(sdirs->clients, &dir, filter_dot, NULL))<0)
	{
		logp("scandir failed for %s in %s: %s\n",
			sdirs->clients, __func__, strerror(errno));
		goto end;
	}
	for(i=0; i<n; i++)
	{
		free_w(&fullpath);
		if(!(fullpath=prepend_s(sdirs->clients, dir[i]->d_name)))
			goto end;
		switch(is_dir(fullpath, dir[i]))
		{
			case 0: continue;
			case 1: break;
			default: logp("is_dir(%s): %s\n",
					fullpath, strerror(errno));
				goto end;
		}

		if(strcmp(sdirs->client, fullpath))
		{
			switch(backup_in_progress(fullpath))
			{
				case 0: break;
				case 1: ret=1;
				default: goto end;
			}
		}

		free_w(&dfiles);
		if(!(dfiles=prepend_s(fullpath, "dfiles"))
		  || lstat(dfiles, &statp))
			continue;

		// Have a good entry. Add it to the list.
		if(strlist_add(s, dfiles, 0))
			goto end;
	}

	ret=0;
end:
	free_w(&fullpath);
	free_w(&dfiles);
	if(dir)
	{
		for(i=0; i<n; i++)
			free(dir[i]);
		free(dir);
	}
	return ret;
}

static int do_unlink(struct blk *oblk, const char *datadir)
{
	int ret=-1;
	char *fullpath=NULL;
	char *savepath=uint64_to_savepathstr(oblk->savepath);
	if(!(fullpath=prepend_s(datadir, savepath)))
		goto end;
	errno=0;
	if(unlink(fullpath) && errno!=ENOENT)
	{
		logp("Could not unlink %s: %s\n", fullpath, strerror(errno));
		goto end;
	}
	logp("Deleted %s\n", savepath);
	ret=0;
end:
	free_w(&fullpath);
	return ret;
}

#ifndef UTEST
static
#endif
int compare_dindexes_and_unlink_datafiles(const char *dindex_old,
	const char *dindex_new, const char *datadir)
{
	int ret=-1;
	struct fzp *nzp=NULL;
	struct fzp *ozp=NULL;
	struct iobuf nbuf;
	struct iobuf obuf;
	struct blk nblk;
	struct blk oblk;

	iobuf_init(&nbuf);
	iobuf_init(&obuf);
	memset(&nblk, 0, sizeof(struct blk));
	memset(&oblk, 0, sizeof(struct blk));
	
	if(!(nzp=fzp_gzopen(dindex_new, "rb"))
	  || !(ozp=fzp_gzopen(dindex_old, "rb")))
		goto end;

	while(nzp || ozp)
	{
		if(nzp
		  && !nbuf.buf)
		{
			switch(iobuf_fill_from_fzp(&nbuf, nzp))
			{
				case 1: fzp_close(&nzp);
					break;
				case 0: if(nbuf.cmd!=CMD_SAVE_PATH)
					{
						logp("unknown cmd in %s: %s\n",
							__func__,
							iobuf_to_printable(&nbuf));
						goto end;
					}
					if(blk_set_from_iobuf_savepath(&nblk,
						&nbuf)) goto end;
					break;
				default: goto end; // Error;
			}
		}

		if(ozp
		  && !obuf.buf)
		{
			switch(iobuf_fill_from_fzp(&obuf, ozp))
			{
				case 1: fzp_close(&ozp);
					break;
				case 0: if(obuf.cmd!=CMD_SAVE_PATH)
					{
						logp("unknown cmd in %s: %c\n",
							__func__, obuf.cmd);
						goto end;
					}
					if(blk_set_from_iobuf_savepath(&oblk,
						&obuf)) goto end;
					break;
				default: goto end; // Error;
			}
		}

		if(nbuf.buf && !obuf.buf)
		{
			// No more from the old file. Time to stop.
			break;
		}
		else if(!nbuf.buf && obuf.buf)
		{
			// No more in the new file. Delete old entry.
			if(do_unlink(&oblk, datadir))
				goto end;
			iobuf_free_content(&obuf);
		}
		else if(!nbuf.buf && !obuf.buf)
		{
			continue;
		}
		else if(nblk.savepath==oblk.savepath)
		{
			// Same, free both and continue;
			iobuf_free_content(&nbuf);
			iobuf_free_content(&obuf);
		}
		else if(nblk.savepath<oblk.savepath)
		{
			// Only in the new file.
			iobuf_free_content(&nbuf);
		}
		else
		{
			// Only in the old file.
			if(do_unlink(&oblk, datadir))
				goto end;
			iobuf_free_content(&obuf);
		}
	}


	ret=0;
end:
	iobuf_free_content(&nbuf);
	iobuf_free_content(&obuf);
	fzp_close(&nzp);
	fzp_close(&ozp);
	return ret;
}

int delete_unused_data_files(struct sdirs *sdirs, int resume)
{
	int ret=-1;
	uint64_t fcount=0;
	char hfile[32];
	char *hlinks=NULL;
	char *fullpath=NULL;
	char *cindex_tmp=NULL;
	char *cindex_new=NULL;
	char *dindex_tmp=NULL;
	char *dindex_new=NULL;
	char *dindex_old=NULL;
	struct strlist *s=NULL;
	struct strlist *slist=NULL;
	struct stat statp;
	struct lock *lock=NULL;

	if(!sdirs)
	{
		logp("No sdirs passed to %s\n", __func__);
		goto end;
	}

	if(resume)
	{
        	// Cannot do it on a resume, or it will delete files that are
        	// referenced in the backup we are resuming.
		logp("Not attempting to clean up unused data files\n");
		logp("because %s is resuming\n", sdirs->clients);
		ret=0;
		goto end;
	}

	if(!(lock=lock_alloc_and_init(sdirs->champ_dindex_lock)))
		goto end;
	lock_get(lock);
	switch(lock->status)
	{
		case GET_LOCK_GOT:
			break;
		default:
			logp("Could not get %s\n", sdirs->champ_dindex_lock);
			logp("This should not happen.\n");
			goto end;
	}

	logp("Attempting to clean up unused data files %s\n", sdirs->clients);

	// Get all lists of files in all backups.
	switch(get_dfiles_to_merge(sdirs, &slist))
	{
		case 0:
			break; // OK.
		case 1:
			// Backups are in progress, cannot continue.
			// But do not return an error.
			ret=0;
		default:
			goto end; // Error.
	}

	if(!(dindex_tmp=prepend_s(sdirs->data, "dindex.tmp"))
	  || !(dindex_old=prepend_s(sdirs->data, "dindex")))
		goto end;

	// Get a list of the files that have been created since last time.
	// (this enables us to clean up data files that were created for
	// interrupted backups).
	if(!(cindex_tmp=prepend_s(sdirs->cfiles, "cindex.tmp"))
	  || recursive_delete(cindex_tmp))
		goto end;
	if(!lstat(sdirs->cfiles, &statp))
	{
		if(mkdir(cindex_tmp, 0777)
		  || !(cindex_new=prepend_s(cindex_tmp, "cindex"))
		  || merge_files_in_dir_no_fcount(cindex_new,
			sdirs->cfiles, merge_dindexes))
				goto end;
		if(!lstat(cindex_new, &statp))
		{
			if(lstat(dindex_old, &statp))
			{
				// The dindex file does not exist.
				// Just rename cindex_new.
				if(do_rename(cindex_new, dindex_old))
					goto end;
			}
			else
			{
				// Merge it into the previous list of files
				// from all backups.
				if(merge_dindexes(dindex_tmp,
					dindex_old, cindex_new)
				  || do_rename(dindex_tmp, dindex_old))
					goto end;
			}
		}
	}

	// Create a directory of hardlinks to each list of files.
	if(!(hlinks=prepend_s(dindex_tmp, "hlinks"))
	  || recursive_delete(dindex_tmp)
	  || mkdir(dindex_tmp, 0777)
	  || mkdir(hlinks, 0777))
		goto end;
	for(s=slist; s; s=s->next)
	{
		snprintf(hfile, sizeof(hfile), "%08" PRIX64, fcount++);
		free_w(&fullpath);
		if(!(fullpath=prepend_s(hlinks, hfile)))
			goto end;
		if(link(s->path, fullpath))
		{
			logp("Could not hardlink %s to %s: %s\n",
				fullpath, s->path, strerror(errno));
			goto end;
		}
	}

	// Create a single list of files in all backups.
	if(!(dindex_new=prepend_s(dindex_tmp, "dindex")))
		goto end;
	if(merge_files_in_dir(dindex_new,
		dindex_tmp, "hlinks", fcount, merge_dindexes))
			goto end;

	if(!lstat(dindex_new, &statp))
	{
		if(!lstat(dindex_old, &statp)
		  && compare_dindexes_and_unlink_datafiles(dindex_old,
			dindex_new, sdirs->data))
				goto end;
		if(do_rename(dindex_new, dindex_old))
			goto end;

		// No longer need the current cfiles directory.
		if(recursive_delete(sdirs->cfiles))
			goto end;
	}

	ret=0;
end:
	strlists_free(&slist);
	if(cindex_tmp) recursive_delete(cindex_tmp);
	if(dindex_tmp) recursive_delete(dindex_tmp);
	lock_release(lock);
	lock_free(&lock);
	free_w(&fullpath);
	free_w(&hlinks);
	free_w(&cindex_tmp);
	free_w(&cindex_new);
	free_w(&dindex_tmp);
	free_w(&dindex_new);
	free_w(&dindex_old);
	return ret;
}
