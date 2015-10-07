#include "../../../burp.h"
#include "../../../alloc.h"
#include "../../../fsops.h"
#include "../../../log.h"
#include "../../../prepend.h"
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

static int do_removal(const char *dindex_new, const char *dindex_old)
{
	// IMPLEMENT THIS
	return 0;
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

	// FIX THIS:
	// Now need to compare the previous global dindex with the newly
	// merged one. If an item appears in the previous one that is not in
	// the new one, we can delete that item!

	printf("%s %s\n", dindex_old, dindex_new);
	if(do_removal(dindex_old, dindex_new))
		goto end;

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
