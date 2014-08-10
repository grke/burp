#include "include.h"
#include "monitor/status_client.h"

#include <netdb.h>
#include <dirent.h>

struct bu *bu_alloc(void)
{
	return (struct bu *)calloc_w(1, sizeof(struct bu), __func__);
}

int bu_init(struct bu *bu, char *fullpath, char *basename,
	char *timestampstr, int hardlinked)
{
	if(!(bu->data=prepend_s(fullpath, "data"))
	  || !(bu->delta=prepend_s(fullpath, "deltas.reverse")))
		goto error;
	bu->path=fullpath;
	bu->basename=basename;
	bu->timestamp=timestampstr;
	bu->hardlinked=hardlinked;
	bu->bno=strtoul(timestampstr, NULL, 10);
	return 0;
error:
	free_w(&bu->data);
	free_w(&bu->delta);
	return -1;
}

void bu_free(struct bu **bu)
{
	if(!bu || !*bu) return;
	free_w(&((*bu)->path));
	free_w(&((*bu)->basename));
	free_w(&((*bu)->data));
	free_w(&((*bu)->delta));
	free_w(&((*bu)->timestamp));
	*bu=NULL;
}

void bu_list_free(struct bu **bu_list)
{
	struct bu *bu;
	struct bu *next;
	for(bu=*bu_list; bu; bu=next)
	{
		next=bu->next;
		bu_free(&bu);
	}
	*bu_list=NULL;
}

static int get_link(const char *dir, const char *lnk, char real[], size_t r)
{
	ssize_t len=0;
	char *tmp=NULL;
	if(!(tmp=prepend_s(dir, lnk)))
		return -1;
	if((len=readlink(tmp, real, r-1))<0) len=0;
	real[len]='\0';
	free(tmp);
	return 0;
}

static int maybe_add_ent(const char *dir, const char *d_name,
	struct bu **bu_list)
{
	int ret=-1;
	char buf[32]="";
	int hardlinked=0;
	struct stat statp;
	char *fullpath=NULL;
	char *timestamp=NULL;
	char *timestampstr=NULL;
	char *hlinkedpath=NULL;
	char *basename=NULL;
	struct bu *bu=NULL;

	if(!(basename=prepend("", d_name, strlen(d_name), ""))
	 || !(fullpath=prepend_s(dir, basename))
	 || !(timestamp=prepend_s(fullpath, "timestamp"))
	 || !(hlinkedpath=prepend_s(fullpath, "hardlinked")))
		goto error;

	if((!lstat(fullpath, &statp) && !S_ISDIR(statp.st_mode))
	  || lstat(timestamp, &statp) || !S_ISREG(statp.st_mode)
	  || timestamp_read(timestamp, buf, sizeof(buf)))
	{
		ret=0; // For resilience.
		goto error;
	}
	free_w(&timestamp);

	if(!(timestampstr=strdup_w(buf, __func__)))
		goto error;

	if(!lstat(hlinkedpath, &statp)) hardlinked++;

	if(!(bu=bu_alloc())
	  || bu_init(bu, fullpath, basename, timestampstr, hardlinked))
		goto error;

	if(*bu_list) bu->next=*bu_list;
	*bu_list=bu;

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

		// Backups that come after hardlinked backups are deletable.
		if(bu->hardlinked && bu->next) bu->next->deletable=1;

		// Also set up reverse linkage.
		bu->prev=last;
		last=bu;
	}

	// The oldest backup is deletable.
	if(bu_list) bu_list->deletable=1;

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

static int rev_alphasort(const struct dirent **a, const struct dirent **b)
{
	static int s;
	if((s=strcmp((*a)->d_name, (*b)->d_name))>0)
		return -1;
	if(s<0)
		return 1;
	return 0;
}

int bu_list_get(struct sdirs *sdirs, struct bu **bu_list)
{
	int i=0;
	int n=0;
	int ret=-1;
	char realwork[32]="";
	char realfinishing[32]="";
	struct dirent **dp=NULL;
	const char *dir=sdirs->client;

	// Find out what certain directories really are, if they exist,
	// so they can be excluded.
	if(get_link(dir, "working", realwork, sizeof(realwork))
	  || get_link(dir, "finishing", realfinishing, sizeof(realfinishing)))
		goto end;

	if((n=scandir(dir, &dp, NULL, rev_alphasort))<0)
	{
		logp("scandir failed in %s: %s\n", __func__, strerror(errno));
		goto end;
	}
	for(i=0; i<n; i++)
	{
		if(!dp[i]->d_ino
		  || !strcmp(dp[i]->d_name, ".")
		  || !strcmp(dp[i]->d_name, ".."))
			continue;
		if(!strcmp(dp[i]->d_name, realwork)
		  || !strcmp(dp[i]->d_name, realfinishing))
			continue;
		if(maybe_add_ent(dir, dp[i]->d_name, bu_list))
			goto end;
	}

	setup_indices(*bu_list);

	ret=0;
end:
	if(dp)
	{
		for(i=0; i<n; i++) free(dp[i]);
		free(dp);
	}
	return ret;
}

int bu_current_get(struct sdirs *sdirs, struct bu **bu_list)
{
	char real[32]="";
	// FIX THIS: should not need to specify "current".
	if(get_link(sdirs->client, "current", real, sizeof(real)))
		return -1;
	return maybe_add_ent(sdirs->client, real, bu_list);
}
