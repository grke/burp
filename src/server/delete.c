#include "include.h"
#include "monitor/status_client.h"

int delete_backup(struct sdirs *sdirs, struct conf *conf, struct bu *bu)
{
	char *deleteme=NULL;

	logp("deleting %s backup %lu\n", conf->cname, bu->bno);

	if(!bu->next)
	{
		char *current=NULL;
		// This is the current backup. Special measures are needed.
		if(!(current=prepend_s(sdirs->client, "current")))
			return -1;
		if(!bu->prev)
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
			target=bu->prev->basename;
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
	  || do_rename(bu->path, deleteme)
	  || recursive_delete(deleteme, NULL, 1))
	{
		logp("Error when trying to delete %s\n", bu->path);
		free(deleteme);
		return -1;
	}
	free(deleteme);

	return 0;
}

static int range_loop(struct sdirs *sdirs, struct conf *cconf,
	struct strlist *keep, unsigned long rmin, struct bu *bu_list,
	struct bu *last, int *deleted)
{
	struct bu *bu=NULL;
	unsigned long r=0;
	unsigned long rmax=0;

	rmax=rmin*keep->next->flag;

	// This is going over each range.
	for(r=rmax; r>rmin; r-=rmin)
	{
		int count=0;
		unsigned long s=r-rmin;

		// Count the backups in the range.
		for(bu=bu_list; bu; bu=bu->next)
		  if(s<bu->trbno && bu->trbno<=r)
			count++;

		// Want to leave one entry in each range.
		if(count<=1) continue;

		// Try to delete from the most recent in each
		// so that hardlinked backups get taken out
		// last.

		for(bu=last; bu; bu=bu->prev)
		{
			if(s<bu->trbno
			  && bu->trbno<=r
			  && bu->deletable)
			{
				if(delete_backup(sdirs, cconf, bu)) return -1;
				(*deleted)++;
				if(--count<=1) break;
			}
		}
	}

	return 0;
}

static int do_delete_backups(struct sdirs *sdirs, struct conf *cconf)
{
	int ret=-1;
	int deleted=0;
	unsigned long m=1;
	struct bu *bu=NULL;
	struct bu *last=NULL;
	struct bu *bu_list=NULL;
	struct strlist *keep=NULL;

	if(bu_list_get(sdirs, &bu_list, 1)) goto end;

	// Find the last entry in the list.
	for(bu=bu_list; bu; bu=bu->next) last=bu;

	// For each of the 'keep' values, generate ranges in which to keep
	// one backup.
	for(keep=cconf->keep; keep; keep=keep->next)
        {
		unsigned long rmin=0;
		rmin=m * keep->flag;

		if(keep->next && range_loop(sdirs, cconf,
			keep, rmin, bu_list, last, &deleted))
				goto end;
		m=rmin;
        }

	// Remove the very oldest backups.
	for(bu=bu_list; bu; bu=bu->next) if(bu->trbno>m) break;

	for(; bu; bu=bu->prev)
	{
		if(delete_backup(sdirs, cconf, bu))
			goto end;
		deleted++;
	}

	ret=deleted;
end:
	bu_list_free(&bu_list);
	return ret;
}

int delete_backups(struct sdirs *sdirs, struct conf *cconf)
{
	// Deleting a backup might mean that more become available to delete.
	// Keep trying to delete until we cannot delete any more.
	while(1) switch(do_delete_backups(sdirs, cconf))
	{
		case 0: return 0;
		case -1: return -1;
		default: continue;
	}
	return -1; // Not reached.
}

int do_delete_server(struct asfd *asfd,
	struct sdirs *sdirs, struct conf *conf, const char *backup)
{
	int ret=-1;
	int found=0;
	unsigned long bno=0;
	struct bu *bu=NULL;
	struct bu *bu_list=NULL;

	logp("in do_delete\n");

	if(bu_list_get(sdirs, &bu_list, 1)
	  || write_status(STATUS_DELETING, NULL, conf))
		goto end;

	if(backup && *backup) bno=strtoul(backup, NULL, 10);

	for(bu=bu_list; bu; bu=bu->next)
	{
		if(!backup || !*backup) continue;
		if(!found
		  && (!strcmp(bu->timestamp, backup)
			|| bu->bno==bno))
		{
			if(bu->deletable)
			{
				found=1;
				if(asfd->write_str(asfd, CMD_GEN, "ok")
				  || delete_backup(sdirs, conf, bu))
					goto end;
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

	if(backup && *backup && !found)
	{
		asfd->write_str(asfd, CMD_ERROR, "backup not found");
		goto end;
	}

	ret=0;
end:
	bu_list_free(&bu_list);
	return ret;
}
