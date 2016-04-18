#include "../../../burp.h"
#include "../../../alloc.h"
#include "../../../fsops.h"
#include "../../../hexmap.h"
#include "../../../log.h"
#include "../../../prepend.h"
#include "../../../protocol2/blk.h"
#include "../../../sbuf.h"
#include "../../../strlist.h"
#include "../../sdirs.h"
#include "../backup_phase4.h"

static int backup_in_progress(const char *fullpath)
{
	int ret=-1;
	struct stat statp;
	char *working=NULL;
	char *finishing=NULL;

	if(!(working=prepend_s(fullpath, "working"))
	  || !(finishing=prepend_s(fullpath, "finishing")))
		goto end;

	if(!lstat(working, &statp)
	  || !lstat(finishing, &statp))
	{
		logp("%s looks like it has a backup in progress.\n",
			fullpath);
		logp("Give up clean up attempt.\n");
		ret=1;
		goto end;
	}
	ret=0;
end:
	free_w(&working);
	free_w(&finishing);
	return ret;
}

static int get_dfiles_to_merge(struct sdirs *sdirs, struct strlist **s)
{
	int i=0;
	int n=0;
	int ret=-1;
	struct stat statp;
	char *fullpath=NULL;
	char *dfiles=NULL;
	struct dirent **dir=NULL;

	logp("Attempting to clean up unused data files %s\n", sdirs->clients);

	if(entries_in_directory_no_sort(sdirs->clients, &dir, &n, 1 /*atime*/))
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
				case 1: ret=0;
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
		for(i=0; i<n; i++) free_v((void **)&dir[i]);
		free_v((void **)&dir);
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
						logp("unknown cmd in %s: %c\n",
							__func__, nbuf.cmd);
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

int delete_unused_data_files(struct sdirs *sdirs)
{
	int ret=-1;
	uint64_t fcount=0;
	char hfile[32];
	char *tmpdir=NULL;
	char *hlinks=NULL;
	char *fullpath=NULL;
	char *dindex_new=NULL;
	char *dindex_old=NULL;
	struct strlist *s=NULL;
	struct strlist *slist=NULL;
	struct stat statp;

	if(get_dfiles_to_merge(sdirs, &slist)
	  || !(dindex_old=prepend_s(sdirs->data, "dindex"))
	  || !(tmpdir=prepend_s(sdirs->data, "dindex.new"))
	  || !(hlinks=prepend_s(tmpdir, "hlinks"))
	  || recursive_delete(tmpdir)
	  || mkdir(tmpdir, 0777)
	  || mkdir(hlinks, 0777))
		goto end;

	for(s=slist; s; s=s->next)
	{
		snprintf(hfile, sizeof(hfile), "%08"PRIX64, fcount++);
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

	if(!(dindex_new=prepend_s(tmpdir, "dindex")))
		goto end;

	if(merge_files_in_dir(dindex_new,
		tmpdir, "hlinks", fcount, merge_dindexes))
			goto end;

	if(!lstat(dindex_new, &statp))
	{
		if(!lstat(dindex_old, &statp)
		  && compare_dindexes_and_unlink_datafiles(dindex_old,
			dindex_new, sdirs->data))
				goto end;
		if(do_rename(dindex_new, dindex_old))
			goto end;
	}

	ret=0;
end:
	strlists_free(&slist);
	if(tmpdir) recursive_delete(tmpdir);
	free_w(&fullpath);
	free_w(&hlinks);
	free_w(&tmpdir);
	free_w(&dindex_new);
	free_w(&dindex_old);
	return ret;
}
