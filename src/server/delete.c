#include "include.h"
#include "monitor/status_client.h"

int delete_backup(struct sdirs *sdirs, struct conf *conf,
	struct bu *arr, int a, int b)
{
	char *deleteme=NULL;

	logp("deleting %s backup %lu\n", conf->cname, arr[b].bno);

	if(b==a-1)
	{
		char *current=NULL;
		// This is the current backup. Special measures are needed.
		if(!(current=prepend_s(sdirs->client, "current")))
			return -1;
		if(!b)
		{
			// After the deletion, there will be no backups left.
			// Just remove the symlink.
			if(unlink(current))
			{
				logp("unlink %s: %s\n",
					current, strerror(errno));
				free(current);
				return -1;
			}
		}
		else
		{
			// Need to point the symlink at the previous backup.
			char *tmp=NULL;
			const char *target=NULL;
			
			if(!(tmp=prepend(current, ".tmp", strlen(".tmp"), "")))
			{
				free(current);
				return -1;
			}
			target=arr[b-1].basename;
			unlink(tmp);
			if(symlink(target, tmp))
			{
				logp("could not symlink '%s' to '%s': %s\n",
					tmp, target, strerror(errno));
				logp("delete failed\n");
				free(tmp);
				free(current);
				return -1;
			}
			// FIX THIS: Race condition: The current link can
			// be deleted and then the rename fail, leaving no
			// current symlink.
			// The administrator will have to recover it manually.
			if(do_rename(tmp, current))
			{
				logp("delete failed\n");
				free(tmp);
				free(current);
				return -1;
			}
			free(tmp);
		}
		free(current);
	}

	if(!(deleteme=prepend_s(sdirs->client, "deleteme"))
	  || do_rename(arr[b].path, deleteme)
	  || recursive_delete(deleteme, NULL, 1))
	{
		logp("Error when trying to delete %s\n", arr[b].path);
		free(deleteme);
		return -1;
	}
	free(deleteme);

	return 0;
}

static int range_loop(struct sdirs *sdirs, struct conf *cconf,
	struct strlist *keep, unsigned long rmin, struct bu *arr, int a,
	int *deleted)
{
	int b=0;
	unsigned long r=0;
	unsigned long rmax=0;

	rmax=rmin*keep->next->flag;

	// This is going over each range.
	for(r=rmax; r>rmin; r-=rmin)
	{
		int count=0;
		unsigned long s=r-rmin;

		// Count the backups in the range.
		for(b=0; b<a; b++)
		  if(s<arr[b].trbno && arr[b].trbno<=r)
			count++;

		// Want to leave one entry in each range.
		if(count>1)
		{
			// Try to delete from the most recent in each
			// so that hardlinked backups get taken out
			// last.

			for(b=a-1; b>=0; b--)
			{
				if(s<arr[b].trbno
				  && arr[b].trbno<=r
				  && arr[b].deletable)
				{
					if(delete_backup(sdirs, cconf,
						arr, a, b)) return -1;
					(*deleted)++;
					if(--count<=1) break;
				}
			}
		}
	}

	return 0;
}

static int do_delete_backups(struct asfd *asfd,
	struct sdirs *sdirs, struct conf *cconf)
{
	int a=0;
	int b=0;
	int ret=-1;
	int deleted=0;
	unsigned long m=1;
	struct bu *arr=NULL;
	struct strlist *keep=NULL;

	if(get_current_backups(asfd, sdirs, &arr, &a, 1)) goto end;

	// For each of the 'keep' values, generate ranges in which to keep
	// one backup.
	for(keep=cconf->keep; keep; keep=keep->next)
        {
		unsigned long rmin=0;
		rmin=m * keep->flag;

		if(keep->next && range_loop(sdirs, cconf,
			keep, rmin, arr, a, &deleted))
				goto end;
		m=rmin;
        }

	// Remove the very oldest backups.
	for(b=0; b<a; b++)
	{
		if(arr[b].trbno>m) break;
	}
	for(; b>=0 && b<a; b--)
	{
		if(delete_backup(sdirs, cconf, arr, a, b))
			goto end;
		deleted++;
	}

	ret=deleted;
end:
	free_current_backups(&arr, a);
	return ret;
}

int delete_backups(struct asfd *asfd, struct sdirs *sdirs, struct conf *cconf)
{
	int deleted=0;
	// Deleting a backup might mean that more become available to get rid
	// of.
	// Keep trying to delete until we cannot delete any more.
	while(1)
	{
		if((deleted=do_delete_backups(asfd, sdirs, cconf))<0)
			return -1;
		else if(!deleted)
			break;
	}
	return 0;
}

int do_delete_server(struct asfd *asfd,
	struct sdirs *sdirs, struct conf *conf, const char *backup)
{
	int a=0;
	int i=0;
	int ret=-1;
	int found=0;
	struct bu *arr=NULL;
	unsigned long bno=0;

	logp("in do_delete\n");

	if(get_current_backups(asfd, sdirs, &arr, &a, 1)
	  || write_status(STATUS_DELETING, NULL, conf))
		goto end;

	if(backup && *backup) bno=strtoul(backup, NULL, 10);

	for(i=0; i<a; i++)
	{
		if(backup && *backup)
		{
			if(!found
			  && (!strcmp(arr[i].timestamp, backup)
				|| arr[i].bno==bno))
			{
				if(arr[i].deletable)
				{
					found=1;
					if(asfd->write_str(asfd, CMD_GEN, "ok")
					  || delete_backup(sdirs, conf,
						arr, a, i)) goto end;
				}
				else
				{
					asfd->write_str(asfd, CMD_ERROR,
						"backup not deletable");
					goto end;
				}
				break;
			}
		}
	}

	if(backup && *backup && !found)
	{
		asfd->write_str(asfd, CMD_ERROR, "backup not found");
		goto end;
	}

	ret=0;
end:
	free_current_backups(&arr, a);
	return ret;
}
