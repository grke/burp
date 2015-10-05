#include "../../../burp.h"
#include "../../../alloc.h"
#include "../../../fsops.h"
#include "../../../log.h"
#include "../../../prepend.h"
#include "../../../strlist.h"
#include "../../sdirs.h"

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

int delete_unused_data_files(struct sdirs *sdirs)
{
	int ret=-1;
	struct strlist *s=NULL;
	struct strlist *slist=NULL;
	if(get_dfiles_to_merge(sdirs, &slist))
		goto end;
	for(s=slist; s; s=s->next)
	{
		logp("dfile: %s\n", s->path);
	}
	ret=0;
end:
	if(ret) strlists_free(&slist);
	return ret;
}
