#include "../burp.h"
#include "../asfd.h"
#include "../bu.h"
#include "../cmd.h"
#include "../cntr.h"
#include "../fsops.h"
#include "../log.h"
#include "../strlist.h"
#include "bu_get.h"
#include "child.h"
#include "sdirs.h"
#include "protocol2/backup_phase4.h"

static int do_rename_w(const char *a, const char *b)
{
	if(do_rename(a, b))
	{
		logp("Error when trying to rename for delete %s\n", a);
		return -1;
	}
	return 0;
}

static int recursive_delete_w(struct sdirs *sdirs, struct bu *bu)
{
	int ret=-1;
	char *timestamp=NULL;
	if(!(timestamp=prepend_s(sdirs->deleteme, "timestamp")))
		goto end;
	// Paranoia - really do not want the deleteme directory to be loaded
	// as if it were a normal storage directory, so delete the timestamp.
	unlink(timestamp);
	if(recursive_delete(sdirs->deleteme))
	{
		logp("Error when trying to delete %s\n", bu->path);
		goto end;
	}
	ret=0;
end:
	free_w(&timestamp);
	return ret;
}

// The failure conditions here are dealt with by the rubble cleaning code.
static int delete_backup(struct sdirs *sdirs, const char *cname, struct bu *bu)
{
	logp("deleting %s backup %lu\n", cname, bu->bno);

	if(sdirs->global_sparse)
	{
		const char *candidate_str=bu->path+strlen(sdirs->base)+1;
		if(remove_from_global_sparse(
			sdirs->global_sparse, candidate_str))
				return -1;
	}

	if(!bu->next && !bu->prev)
	{
		// The current, and only, backup.
		if(do_rename_w(bu->path, sdirs->deleteme)) return -1;
		// If interrupted here, there will be a dangling 'current'
		// symlink.
		if(unlink(sdirs->current))
		{
			logp("unlink %s: %s\n",
				sdirs->current, strerror(errno));
			return -1;
		}
		return recursive_delete_w(sdirs, bu);
	}
	if(!bu->next && bu->prev)
	{
		// The current backup. There are other backups left.
		// Need to point the symlink at the previous backup.
		const char *target=NULL;
		
		target=bu->prev->basename;
		unlink(sdirs->currenttmp);
		if(symlink(target, sdirs->currenttmp))
		{
			logp("could not symlink '%s' to '%s': %s\n",
				sdirs->currenttmp, target, strerror(errno));
			return -1;
		}
		// If interrupted here, there is a currenttmp and a current
		// symlink, and they both point to valid directories.
		if(do_rename_w(bu->path, sdirs->deleteme))
			return -1;
		// If interrupted here, there is a currenttmp and a current
		// symlink, and the current link is dangling.
		if(do_rename_w(sdirs->currenttmp, sdirs->current))
			return -1;
		// If interrupted here, moving the symlink could have failed
		// after current was deleted but before currenttmp was renamed.
		if(recursive_delete_w(sdirs, bu))
			return -1;
		return 0;
	}

	// It is not the current backup.
	if(do_rename_w(bu->path, sdirs->deleteme)
	  || recursive_delete_w(sdirs, bu))
		return -1;
	return 0;
}

static int range_loop(struct sdirs *sdirs, const char *cname,
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
			  && bu->trbno<r
			  && (bu->flags & BU_DELETABLE))
			{
				if(delete_backup(sdirs, cname, bu)) return -1;
				(*deleted)++;
				if(--count<=1) break;
			}
		}
	}

	return 0;
}

static int do_delete_backups(struct sdirs *sdirs, const char *cname,
	struct strlist *keep, struct bu *bu_list)
{
	int ret=-1;
	int deleted=0;
	unsigned long m=1;
	struct bu *bu=NULL;
	struct bu *last=NULL;
	struct strlist *k=NULL;

	// Find the last entry in the list.
	for(bu=bu_list; bu; bu=bu->next) last=bu;

	// For each of the 'keep' values, generate ranges in which to keep
	// one backup.
	for(k=keep; k; k=k->next)
        {
		unsigned long rmin=0;
		rmin=m * k->flag;

		if(k->next && range_loop(sdirs, cname,
			k, rmin, bu_list, last, &deleted))
				goto end;
		m=rmin;
        }

	// Remove the very oldest backups.
	for(bu=bu_list; bu; bu=bu->next) if(bu->trbno>m) break;

	for(; bu; bu=bu->prev)
	{
		if(delete_backup(sdirs, cname, bu))
			goto end;
		deleted++;
	}

	ret=deleted;
end:
	return ret;
}

int delete_backups(struct sdirs *sdirs,
	const char *cname, struct strlist *keep)
{
	int ret=-1;
	struct bu *bu_list=NULL;
	// Deleting a backup might mean that more become available to delete.
	// Keep trying to delete until we cannot delete any more.
	while(1)
	{
		if(bu_get_list(sdirs, &bu_list)) goto end;
		switch(do_delete_backups(sdirs, cname, keep, bu_list))
		{
			case 0: ret=0; goto end;
			case -1: ret=-1; goto end;
			default: break;
		}
		bu_list_free(&bu_list);
	}
end:
	bu_list_free(&bu_list);
	return ret;
}

int do_delete_server(struct asfd *asfd,
	struct sdirs *sdirs, struct cntr *cntr,
	const char *cname, const char *backup)
{
	int ret=-1;
	int found=0;
	unsigned long bno=0;
	struct bu *bu=NULL;
	struct bu *bu_list=NULL;

	logp("in do_delete\n");

	if(bu_get_list(sdirs, &bu_list)
	  || write_status(CNTR_STATUS_DELETING, NULL, cntr))
		goto end;

	if(backup && *backup) bno=strtoul(backup, NULL, 10);

	for(bu=bu_list; bu; bu=bu->next)
	{
		if(!backup || !*backup) continue;
		if(!found
		  && (!strcmp(bu->timestamp, backup)
			|| bu->bno==bno))
		{
			if(bu->flags & BU_DELETABLE)
			{
				found=1;
				if(asfd->write_str(asfd, CMD_GEN, "ok")
				  || delete_backup(sdirs, cname, bu))
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
