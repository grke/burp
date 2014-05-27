#include "include.h"
#include "monitor/status_client.h"

#include <netdb.h>
#include <dirent.h>

static int bu_cmp(const void *va, const void *vb)
{
	const struct bu *a=(struct bu *)va;
	const struct bu *b=(struct bu *)vb;
	if(     a->index > b->index) return 1;
	else if(a->index < b->index) return -1;
	return 0;
}

void free_current_backups(struct bu **arr, int a)
{
	int b=0;
	for(b=0; b<a; b++)
	{
		if((*arr)[b].path)
			{ free((*arr)[b].path); (*arr)[b].path=NULL; }
		if((*arr)[b].basename)
			{ free((*arr)[b].basename); (*arr)[b].basename=NULL; }
		if((*arr)[b].data)
			{ free((*arr)[b].data); (*arr)[b].data=NULL; }
		if((*arr)[b].delta)
			{ free((*arr)[b].delta); (*arr)[b].delta=NULL; }
		if((*arr)[b].timestamp)
			{ free((*arr)[b].timestamp); (*arr)[b].timestamp=NULL; }
	}
	free(*arr);
	*arr=NULL;
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

int get_current_backups_str(struct asfd *asfd,
	const char *dir, struct bu **arr, int *a, int log)
{
	int i=0;
	int j=0;
	int tr=0;
	int ret=0;
	DIR *d=NULL;
	char buf[32]="";
	char realwork[32]="";
	char realfinishing[32]="";
	struct dirent *dp=NULL;

	// Find out what certain directories really are, if they exist,
	// so they can be excluded.
	if(get_link(dir, "working", realwork, sizeof(realwork))
	  || get_link(dir, "finishing", realfinishing, sizeof(realfinishing)))
		return -1;
	if(!(d=opendir(dir)))
	{
		if(log) log_and_send(asfd, "could not open backup directory");
		return -1;
	}
	while((dp=readdir(d)))
	{
		int hardlinked=0;
		struct stat statp;
		char *fullpath=NULL;
		char *timestamp=NULL;
		char *timestampstr=NULL;
		char *hlinkedpath=NULL;
		char *basename=NULL;

		if(dp->d_ino==0
		  || !strcmp(dp->d_name, ".")
		  || !strcmp(dp->d_name, "..")
		  || !strcmp(dp->d_name, realwork)
		  || !strcmp(dp->d_name, realfinishing))
			continue;
		if(!(basename=prepend("",
			dp->d_name, strlen(dp->d_name), ""))
		 || !(fullpath=prepend_s(dir, basename))
		 || !(timestamp=prepend_s(fullpath, "timestamp"))
		 || !(hlinkedpath=prepend_s(fullpath, "hardlinked")))
		{
			ret=-1;
			if(basename) free(basename);
			if(fullpath) free(fullpath);
			if(timestamp) free(timestamp);
			break;
		}
		if((!lstat(fullpath, &statp) && !S_ISDIR(statp.st_mode))
		  || lstat(timestamp, &statp) || !S_ISREG(statp.st_mode)
		  || timestamp_read(timestamp, buf, sizeof(buf))
		  || !(timestampstr=strdup(buf)))
		{
			free(basename);
			free(fullpath);
			free(timestamp);
			free(hlinkedpath);
			continue;
		}
		free(timestamp);

		if(!lstat(hlinkedpath, &statp)) hardlinked++;

		if(!(*arr=(struct bu *)
			realloc_w(*arr,(i+1)*sizeof(struct bu), __func__))
		  || !((*arr)[i].data=prepend_s(fullpath, "data"))
		  || !((*arr)[i].delta=prepend_s(fullpath, "deltas.reverse")))
		{
			if(log) log_and_send_oom(asfd, __func__);
			free(basename);
			free(timestampstr);
			free(fullpath);
			free(hlinkedpath);
			break;
		}
		(*arr)[i].path=fullpath;
		(*arr)[i].basename=basename;
		(*arr)[i].timestamp=timestampstr;
		(*arr)[i].hardlinked=hardlinked;
		(*arr)[i].deletable=0;
		(*arr)[i].index=strtoul(timestampstr, NULL, 10);
		(*arr)[i].trindex=0;
		i++;
	}
	closedir(d);

	if(*arr) qsort(*arr, i, sizeof(struct bu), bu_cmp);

	if(i>=1)
	{
		tr=(*arr)[i-1].index;
		// The oldest backup is deletable.
		(*arr)[0].deletable=1;
	}

	for(j=0; j<i-1; j++)
	{
		// Backups that come after hardlinked backups are deletable.
		if((*arr)[j].hardlinked) (*arr)[j+1].deletable=1;
	}
	if(!ret)
	{
		if(tr) for(j=0; j<i; j++)
		{
			// Transpose indexes so that the oldest index is set
			// to 1.
			(*arr)[j].trindex=tr-(*arr)[j].index+1;
			//printf("%lu: %lu\n",
			//	(*arr)[j].index, (*arr)[j].trindex);
		}
		*a=i;
	}
		  
	return ret;
}

int get_current_backups(struct asfd *asfd,
	struct sdirs *sdirs, struct bu **arr, int *a, int log)
{
	return get_current_backups_str(asfd, sdirs->client, arr, a, log);
}

int delete_backup(struct sdirs *sdirs, struct conf *conf,
	struct bu *arr, int a, int b)
{
	char *deleteme=NULL;

	logp("deleting %s backup %lu\n", conf->cname, arr[b].index);

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

int do_remove_old_backups(struct asfd *asfd,
	struct sdirs *sdirs, struct conf *cconf)
{
	int a=0;
	int b=0;
	int ret=0;
	int deleted=0;
	unsigned long m=1;
	struct bu *arr=NULL;
	struct strlist *keep=NULL;

	if(get_current_backups(asfd, sdirs, &arr, &a, 1)) return -1;

	// For each of the 'keep' values, generate ranges in which to keep
	// one backup.
	for(keep=cconf->keep; keep; keep=keep->next)
        {
		unsigned long n=0;
		n=m * keep->flag;

                //printf("keep: %d - m:%lu n:%lu\n",
		//	x, keep->flag, m, n);
		if(keep->next)
		{
			unsigned long r=0;
			unsigned long s=0;
			unsigned long upto=0;
			upto=n*keep->next->flag;
			//printf("upto: %lu\n", upto);
			// This is going over each range.
			for(r=upto; r>n; r-=n)
			{
				int count=0;
				s=r-n;
				//printf("   try: %lu - %lu\n", s, r);

				// Count the backups in the range.
				for(b=0; b<a; b++)
				{
					if(s<arr[b].trindex
					   && arr[b].trindex<=r)
					{
						//printf("     check backup %lu (%lu) %d\n", arr[b].index, arr[b].trindex, arr[b].deletable);
						count++;
					}
				}

				// Want to leave one entry in each range.
				if(count>1)
				{
				  // Try to delete from the most recent in each
				  // so that hardlinked backups get taken out
				  // last.
				  
				  for(b=a-1; b>=0; b--)
				  {
				    if(s<arr[b].trindex
				       && arr[b].trindex<=r
				       && arr[b].deletable)
				    {
					//printf("deleting backup %lu (%lu)\n", arr[b].index, arr[b].trindex);
					if(delete_backup(sdirs, cconf,
						arr, a, b))
					{
						ret=-1;
						break;
					}
					deleted++;
				  	if(--count<=1) break;
				    }
				  }
				}

				if(ret) break;
			}
		}
		m=n;

		if(ret) break;
        }

	if(!ret)
	{
		// Remove the very oldest backups.
		//printf("back from: %lu\n", m);
		for(b=0; b<a; b++)
		{
			//printf(" %d: %lu (%lu)\n", b, arr[b].index, arr[b].trindex);
			if(arr[b].trindex>m) break;
		}
		for(; b>=0 && b<a; b--)
		{
			if(delete_backup(sdirs, cconf, arr, a, b))
			{
				ret=-1;
				break;
			}
			deleted++;
		}
	}

	free_current_backups(&arr, a);

	if(ret) return ret;

	return deleted;
}

int remove_old_backups(struct asfd *asfd,
	struct sdirs *sdirs, struct conf *cconf)
{
	int deleted=0;
	// Deleting a backup might mean that more become available to get rid
	// of.
	// Keep trying to delete until we cannot delete any more.
	while(1)
	{
		if((deleted=do_remove_old_backups(asfd, sdirs, cconf))<0)
			return -1;
		else if(!deleted)
			break;
	}
	return 0;
}
