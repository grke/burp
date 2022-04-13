#include "../burp.h"
#include "../alloc.h"
#include "../bu.h"
#include "../fsops.h"
#include "../log.h"
#include "../prepend.h"
#include "sdirs.h"
#include "timestamp.h"
#include "bu_get.h"

static int get_link(const char *dir, const char *lnk, char real[], size_t r)
{
	return readlink_w_in_dir(dir, lnk, real, r);
}

static void have_backup_file_name(struct bu *bu,
        const char *file, uint32_t bit)
{
	struct stat statp;
	static char path[256]="";
	snprintf(path, sizeof(path), "%s/%s", bu->path, file);
	if(lstat(path, &statp)) return;
	bu->flags|=bit;
}

static void have_backup_file_name_w(struct bu *bu,
	const char *file, uint32_t bit)
{
	char compressed[32];
	snprintf(compressed, sizeof(compressed), "%s.gz", file);
	have_backup_file_name(bu, file, bit);
	have_backup_file_name(bu, compressed, bit);
}

static int maybe_add_ent(const char *dir, const char *d_name,
	struct bu **bu_list, uint16_t flags,
	int include_working)
{
	int ret=-1;
	char buf[38]="";
	struct stat statp;
	char *fullpath=NULL;
	char *timestamp=NULL;
	char *timestampstr=NULL;
	char *hlinkedpath=NULL;
	char *basename=NULL;
	struct bu *bu=NULL;

	if(!(basename=prepend("", d_name))
	 || !(fullpath=prepend_s(dir, basename))
	 || !(timestamp=prepend_s(fullpath, "timestamp"))
	 || !(hlinkedpath=prepend_s(fullpath, "hardlinked")))
		goto error;

	if((!lstat(fullpath, &statp) && !S_ISDIR(statp.st_mode))
	  || lstat(timestamp, &statp) || !S_ISREG(statp.st_mode)
	  || timestamp_read(timestamp, buf, sizeof(buf))
	// A bit of paranoia to protect against loading directories moved
	// aside as if they were real storage directories.
	  || strncmp(buf, d_name, 8))
	{
		ret=0; // For resilience.
		goto error;
	}

	free_w(&timestamp);

	if(!(timestampstr=strdup_w(buf, __func__)))
		goto error;

	if(!lstat(hlinkedpath, &statp)) flags|=BU_HARDLINKED;

	if(!(bu=bu_alloc())
	  || bu_init(bu, fullpath, basename, timestampstr, flags))
		goto error;

	if(*bu_list) bu->next=*bu_list;
	*bu_list=bu;
	have_backup_file_name_w(bu, "manifest", BU_MANIFEST);
	if(include_working)
	{
		have_backup_file_name_w(bu, "log", BU_LOG_BACKUP);
		have_backup_file_name_w(bu, "restorelog", BU_LOG_RESTORE);
		have_backup_file_name_w(bu, "verifylog", BU_LOG_VERIFY);
		if(!(bu->flags & BU_STATS_BACKUP))
		  have_backup_file_name(bu, "backup_stats", BU_STATS_BACKUP);
		if(!(bu->flags & BU_STATS_RESTORE))
		  have_backup_file_name(bu, "restore_stats", BU_STATS_RESTORE);
		if(!(bu->flags & BU_STATS_VERIFY))
		  have_backup_file_name(bu, "verify_stats", BU_STATS_VERIFY);
	}

	free_w(&hlinkedpath);
	return 0;
error:
	free_w(&basename);
	free_w(&fullpath);
	free_w(&timestamp);
	free_w(&timestampstr);
	free_w(&hlinkedpath);
	return ret;
}

static void setup_indices(struct bu *bu_list)
{
	int i;
	int tr=0;
	struct bu *bu=NULL;
	struct bu *last=NULL;

	i=1;
	for(bu=bu_list; bu; bu=bu->next)
	{
		// Enumerate the position of each entry.
		bu->index=i++;

		// Backups that come after hardlinked backups are
		// deletable.
		if((bu->flags & BU_HARDLINKED) && bu->next)
			bu->next->flags|=BU_DELETABLE;

		// Also set up reverse linkage.
		bu->prev=last;
		last=bu;
	}

	// The oldest backup is deletable.
	if(bu_list) bu_list->flags|=BU_DELETABLE;

	if(last)
	{

		if((tr=last->bno))
		{
			// Transpose bnos so that the oldest bno is set to 1.
			for(bu=bu_list; bu; bu=bu->next)
				bu->trbno=tr-bu->bno+1;
		}
	}
}

static int do_bu_get_list(struct sdirs *sdirs,
	struct bu **bu_list, int include_working)
{
	int i=0;
	int n=0;
	int ret=-1;
	char realwork[38]="";
	char realfinishing[38]="";
	char realcurrent[38]="";
	struct dirent **dp=NULL;
	const char *dir=NULL;
	uint16_t flags=0;
	struct stat statp;

	if(!sdirs)
	{
		logp("%s() called with NULL sdirs\n", __func__);
		goto end;
	}

	dir=sdirs->client;

	if(get_link(dir, "working", realwork, sizeof(realwork))
	  || get_link(dir, "finishing", realfinishing, sizeof(realfinishing))
	  || get_link(dir, "current", realcurrent, sizeof(realcurrent)))
		goto end;

	if(!stat(dir, &statp)
	  && (n=scandir(dir, &dp, filter_dot, alphasort))<0)
	{
		logp("scandir failed in %s: %s\n", __func__, strerror(errno));
		goto end;
	}
	i=n;
	while(i--)
	{
		// Each storage directory starts with a digit. The 'deleteme'
		// directory does not. This check avoids loading 'deleteme'
		// as a storage directory.
		if(!isdigit(dp[i]->d_name[0]))
			continue;
		flags=0;
		if(!strcmp(dp[i]->d_name, realcurrent))
		{
			flags|=BU_CURRENT;
		}
		else if(!strcmp(dp[i]->d_name, realwork))
		{
			if(!include_working) continue;
			flags|=BU_WORKING;
		}
		else if(!strcmp(dp[i]->d_name, realfinishing))
		{
			if(!include_working) continue;
			flags|=BU_FINISHING;
		}
		if(maybe_add_ent(dir, dp[i]->d_name, bu_list, flags,
			include_working)) goto end;
	}

	setup_indices(*bu_list);

	ret=0;
end:
	if(dp)
	{
		for(i=0; i<n; i++)
			free(dp[i]);
		free(dp);
	}
	return ret;
}

int bu_get_list(struct sdirs *sdirs, struct bu **bu_list)
{
	return do_bu_get_list(sdirs, bu_list, 0/*include_working*/);
}

int bu_get_list_with_working(struct sdirs *sdirs, struct bu **bu_list)
{
	return do_bu_get_list(sdirs, bu_list, 1/*include_working*/);
}

int bu_get_current(struct sdirs *sdirs, struct bu **bu_list)
{
	char real[38]="";
	// FIX THIS: should not need to specify "current".
	if(get_link(sdirs->client, "current", real, sizeof(real)))
		return -1;
	return maybe_add_ent(sdirs->client, real, bu_list, BU_CURRENT,
		0/*include_working*/);
}
