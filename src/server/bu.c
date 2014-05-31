#include "include.h"
#include "monitor/status_client.h"

#include <netdb.h>
#include <dirent.h>

static int bu_cmp(const void *va, const void *vb)
{
	const struct bu *a=(struct bu *)va;
	const struct bu *b=(struct bu *)vb;
	if(     a->bno > b->bno) return 1;
	else if(a->bno < b->bno) return -1;
	return 0;
}

void bu_free(struct bu **arr, int a)
{
	int b=0;
	for(b=0; b<a; b++)
	{
		free_w(&((*arr)[b].path));
		free_w(&((*arr)[b].basename));
		free_w(&((*arr)[b].data));
		free_w(&((*arr)[b].delta));
		free_w(&((*arr)[b].timestamp));
	}
	free_v((void **)arr);
}

static int get_link(const char *dir, const char *lnk, char real[], size_t r)
{
	ssize_t len=0;
	char *tmp=NULL;
	if(!(tmp=prepend_s(dir, lnk)))
	{
		log_out_of_memory(__func__);
		return -1;
	}
	if((len=readlink(tmp, real, r-1))<0) len=0;
	real[len]='\0';
	free(tmp);
	return 0;
}

static int maybe_add_ent(struct asfd *asfd,
	const char *dir, const char *d_name,
	struct bu **arr, int *a, int log)
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

	if(!(basename=prepend("", d_name, strlen(d_name), ""))
	 || !(fullpath=prepend_s(dir, basename))
	 || !(timestamp=prepend_s(fullpath, "timestamp"))
	 || !(hlinkedpath=prepend_s(fullpath, "hardlinked")))
		goto error;

	if((!lstat(fullpath, &statp) && !S_ISDIR(statp.st_mode))
	  || lstat(timestamp, &statp) || !S_ISREG(statp.st_mode)
	  || timestamp_read(timestamp, buf, sizeof(buf)))
	{
		ret=0;
		goto error;
	}
	free_w(&timestamp);

	if(!(timestampstr=strdup_w(buf, __func__)))
		goto error;

	if(!lstat(hlinkedpath, &statp)) hardlinked++;

	if(!(*arr=(struct bu *)
		realloc_w(*arr,((*a)+1)*sizeof(struct bu), __func__))
	  || !((*arr)[*a].data=prepend_s(fullpath, "data"))
	  || !((*arr)[*a].delta=prepend_s(fullpath, "deltas.reverse")))
	{
		if(log) log_and_send_oom(asfd, __func__);
		goto error;
	}
	(*arr)[*a].path=fullpath;
	(*arr)[*a].basename=basename;
	(*arr)[*a].timestamp=timestampstr;
	(*arr)[*a].hardlinked=hardlinked;
	(*arr)[*a].deletable=0;
	(*arr)[*a].bno=strtoul(timestampstr, NULL, 10);
	(*arr)[*a].trbno=0;
	(*arr)[*a].index=*a;
	(*a)++;

	return 0;
error:
	free_w(&basename);
	free_w(&fullpath);
	free_w(&timestamp);
	free_w(&timestampstr);
	free_w(&hlinkedpath);
	return ret;
}

int bu_get_str(struct asfd *asfd,
	const char *dir, struct bu **arr, int *a, int log)
{
	int i=0;
	int tr=0;
	int ret=-1;
	DIR *d=NULL;
	char realwork[32]="";
	char realfinishing[32]="";
	struct dirent *dp=NULL;

	// Find out what certain directories really are, if they exist,
	// so they can be excluded.
	if(get_link(dir, "working", realwork, sizeof(realwork))
	  || get_link(dir, "finishing", realfinishing, sizeof(realfinishing)))
		goto end;
	if(!(d=opendir(dir)))
	{
		if(log) log_and_send(asfd, "could not open backup directory");
		goto end;
	}
	*a=0;
	while((dp=readdir(d)))
	{
		if(!dp->d_ino
		  || !strcmp(dp->d_name, ".")
		  || !strcmp(dp->d_name, "..")
		  || !strcmp(dp->d_name, realwork)
		  || !strcmp(dp->d_name, realfinishing))
			continue;
		 if(maybe_add_ent(asfd, dir, dp->d_name, arr, a, log))
			goto end;
	}

	if(*arr) qsort(*arr, *a, sizeof(struct bu), bu_cmp);

	if(*a>=1)
	{
		tr=(*arr)[(*a)-1].bno;
		// The oldest backup is deletable.
		(*arr)[0].deletable=1;
	}

	// Backups that come after hardlinked backups are deletable.
	for(i=0; i<(*a)-1; i++)
		if((*arr)[i].hardlinked) (*arr)[i+1].deletable=1;

	// Transpose bnos so that the oldest bno is set to 1.
	if(tr) for(i=0; i<*a; i++)
		(*arr)[i].trbno=tr-(*arr)[i].bno+1;

	ret=0;
end:
	if(d) closedir(d);
	return ret;
}

int bu_get(struct asfd *asfd,
	struct sdirs *sdirs, struct bu **arr, int *a, int log)
{
	return bu_get_str(asfd, sdirs->client, arr, a, log);
}
