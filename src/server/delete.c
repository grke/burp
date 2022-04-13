#include "../burp.h"
#include "../alloc.h"
#include "../asfd.h"
#include "../bu.h"
#include "../cmd.h"
#include "../cntr.h"
#include "../cstat.h"
#include "../fsops.h"
#include "../log.h"
#include "../prepend.h"
#include "../strlist.h"
#include "bu_get.h"
#include "child.h"
#include "sdirs.h"
#include "delete.h"

static int do_rename_w(const char *a, const char *b,
	const char *cname, struct bu *bu)
{
	int ret=-1;
	char *target=NULL;
	char new_name[256]="";
	snprintf(new_name, sizeof(new_name), "%s-%s", cname, bu->basename);
	if(!(target=prepend_s(b, new_name))
	  || build_path_w(target))
		goto end;
	if(do_rename(a, target))
	{
		logp("Error when trying to rename for delete %s\n", a);
		goto end;
	}
	ret=0;
end:
	free_w(&target);
	return ret;
}

static int recursive_delete_w(struct sdirs *sdirs, struct bu *bu,
	const char *manual_delete)
{
	if(manual_delete) return 0;
	if(recursive_delete(sdirs->deleteme))
	{
		logp("Error when trying to delete %s\n", bu->path);
		return -1;
	}
	return 0;
}

// The failure conditions here are dealt with by the rubble cleaning code.
static int delete_backup(struct sdirs *sdirs, const char *cname, struct bu *bu,
	const char *manual_delete)
{
	logp("deleting %s backup %" PRId64 "\n", cname, bu->bno);

	if(!bu->next && !bu->prev)
	{
		// The current, and only, backup.
		if(do_rename_w(bu->path, sdirs->deleteme, cname, bu))
			return -1;
		// If interrupted here, there will be a dangling 'current'
		// symlink.
		if(unlink(sdirs->current))
		{
			logp("unlink %s: %s\n",
				sdirs->current, strerror(errno));
			return -1;
		}
		return recursive_delete_w(sdirs, bu, manual_delete);
	}
	if(!bu->next && bu->prev)
	{
		// The current backup. There are other backups left.
		// Need to point the symlink at the previous backup.
		const char *target=NULL;
		
		target=bu->prev->basename;
		unlink(sdirs->currenttmp);
		if(do_symlink(target, sdirs->currenttmp))
			return -1;
		// If interrupted here, there is a currenttmp and a current
		// symlink, and they both point to valid directories.
		if(do_rename_w(bu->path, sdirs->deleteme, cname, bu))
			return -1;
		// If interrupted here, there is a currenttmp and a current
		// symlink, and the current link is dangling.
		if(do_rename(sdirs->currenttmp, sdirs->current))
			return -1;
		// If interrupted here, moving the symlink could have failed
		// after current was deleted but before currenttmp was renamed.
		if(recursive_delete_w(sdirs, bu, manual_delete))
			return -1;
		return 0;
	}

	// It is not the current backup.
	if(do_rename_w(bu->path, sdirs->deleteme, cname, bu)
	  || recursive_delete_w(sdirs, bu, manual_delete))
		return -1;
	return 0;
}

static int range_loop(struct sdirs *sdirs, const char *cname,
	struct strlist *keep, unsigned long rmin, struct bu *bu_list,
	struct bu *last, const char *manual_delete, int *deleted)
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
				if(delete_backup(sdirs, cname, bu,
					manual_delete)) return -1;
				(*deleted)++;
				if(--count<=1) break;
			}
		}
	}

	return 0;
}

static int do_delete_backups(struct sdirs *sdirs, const char *cname,
	struct strlist *keep, struct bu *bu_list, const char *manual_delete)
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
			k, rmin, bu_list, last, manual_delete, &deleted))
				goto end;
		m=rmin;
        }

	// Remove the very oldest backups.
	for(bu=bu_list; bu; bu=bu->next) if(bu->trbno>m) break;

	for(; bu; bu=bu->prev)
	{
		if(delete_backup(sdirs, cname, bu, manual_delete))
			goto end;
		deleted++;
	}

	ret=deleted;
end:
	return ret;
}

int delete_backups(struct sdirs *sdirs,
	const char *cname, struct strlist *keep, const char *manual_delete)
{
	int ret=-1;
	struct bu *bu_list=NULL;
	// Deleting a backup might mean that more become available to delete.
	// Keep trying to delete until we cannot delete any more.
	while(1)
	{
		if(bu_get_list(sdirs, &bu_list)) goto end;
		switch(do_delete_backups(sdirs, cname, keep, bu_list,
			manual_delete))
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
	struct sdirs *sdirs, struct conf **confs,
	const char *cname, const char *backup, const char *manual_delete)
{
	int ret=-1;
	int found=0;
	unsigned long bno=0;
	struct bu *bu=NULL;
	struct bu *bu_list=NULL;
	struct cntr *cntr=NULL;
	if(confs)
		cntr=get_cntr(confs);

	logp("in do_delete\n");

	if(bu_get_list(sdirs, &bu_list))
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
				if(cntr)
					cntr->bno=(int)bu->bno;
				if(timed_operation_status_only(
					CNTR_STATUS_DELETING, NULL, confs))
						goto end;
				if(asfd->write_str(asfd, CMD_GEN, "ok")
				  || delete_backup(sdirs, cname, bu,
					manual_delete))
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
