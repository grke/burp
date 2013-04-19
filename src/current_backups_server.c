#include "burp.h"
#include "prog.h"
#include "msg.h"
#include "lock.h"
#include "rs_buf.h"
#include "handy.h"
#include "asyncio.h"
#include "zlibio.h"
#include "counter.h"
#include "dpth.h"
#include "sbuf.h"
#include "current_backups_server.h"

#include <netdb.h>
#include <librsync.h>
#include <math.h>

int recursive_hardlink(const char *src, const char *dst, const char *client, struct cntr *p1cntr, struct cntr *cntr, struct config *conf)
{
	int n=-1;
	int ret=0;
	struct dirent **dir;
	char *tmp=NULL;
	//logp("in rec hl: %s %s\n", src, dst);
	if(!(tmp=prepend_s(dst, "dummy", strlen("dummy"))))
		return -1;
	if(mkpath(&tmp, dst))
	{
		logp("could not mkpath for %s\n", tmp);
		free(tmp);
		return -1;
	}
	free(tmp);

	if((n=scandir(src, &dir, 0, 0))<0)
	{
		logp("recursive_hardlink scandir %s: %s\n",
			src, strerror(errno));
		return -1;
	}
	while(n--)
	{
		struct stat statp;
		char *fullpatha=NULL;
		char *fullpathb=NULL;
		if(dir[n]->d_ino==0
		  || !strcmp(dir[n]->d_name, ".")
		  || !strcmp(dir[n]->d_name, ".."))
			{ free(dir[n]); continue; }
		if(!(fullpatha=prepend_s(src,
			dir[n]->d_name, strlen(dir[n]->d_name)))
		|| !(fullpathb=prepend_s(dst,
			dir[n]->d_name, strlen(dir[n]->d_name))))
		{
			if(fullpatha) free(fullpatha);
			if(fullpathb) free(fullpathb);
			break;
		}

#ifdef _DIRENT_HAVE_D_TYPE
// Faster evaluation on most systems.
		if(dir[n]->d_type==DT_DIR)
		{
			if(recursive_hardlink(fullpatha, fullpathb, client,
				p1cntr, cntr, conf))
			{
				free(fullpatha);
				free(fullpathb);
				break;
			}
		}
		else
#endif
		// Otherwise, we have to do an lstat() anyway, because we
		// will need to check the number of hardlinks in do_link().
		if(lstat(fullpatha, &statp))
		{
			logp("could not lstat %s\n", fullpatha);
		}
		else if(S_ISDIR(statp.st_mode))
		{
			if(recursive_hardlink(fullpatha, fullpathb, client,
				p1cntr, cntr, conf))
			{
				free(fullpatha);
				free(fullpathb);
				break;
			}
		}
		else
		{
			//logp("hardlinking %s to %s\n", fullpathb, fullpatha);
			write_status(client, STATUS_SHUFFLING, fullpathb,
				p1cntr, cntr);
			if(do_link(fullpatha, fullpathb, &statp, conf,
				FALSE /* do not overwrite target */))
			{
				free(fullpatha);
				free(fullpathb);
				break;
			}
		}
		free(fullpatha);
		free(fullpathb);
		free(dir[n]);
	}
	if(n>0)
	{
		ret=-1;
		for(; n>0; n--) free(dir[n]);
	}
	free(dir);

	return ret;
}

#define RECDEL_ERROR			-1
#define RECDEL_OK			0
#define RECDEL_ENTRIES_REMAINING	1

int recursive_delete(const char *d, const char *file, bool delfiles)
{
	int n=-1;
	int ret=RECDEL_OK;
	struct dirent **dir;
	struct stat statp;
	char *directory=NULL;

	if(!file)
	{
		if(!(directory=prepend_s(d, "", 0))) return RECDEL_ERROR;
	}
	else if(!(directory=prepend_s(d, file, strlen(file))))
	{
		log_out_of_memory(__FUNCTION__);
		return RECDEL_ERROR;
	}

	if(lstat(directory, &statp))
	{
		// path does not exist.
		free(directory);
		return RECDEL_OK;
	}

	if((n=scandir(directory, &dir, 0, 0))<0)
	{
		logp("scandir %s: %s\n", directory, strerror(errno));
		free(directory);
		return RECDEL_ERROR;
	}
	while(n--)
	{
		char *fullpath=NULL;
		if(dir[n]->d_ino==0
		  || !strcmp(dir[n]->d_name, ".")
		  || !strcmp(dir[n]->d_name, ".."))
			{ free(dir[n]); continue; }
		if(!(fullpath=prepend_s(directory,
			dir[n]->d_name, strlen(dir[n]->d_name))))
				break;

		if(is_dir(fullpath, dir[n]))
		{
			int r;
			if((r=recursive_delete(directory,
				dir[n]->d_name, delfiles))==RECDEL_ERROR)
			{
				free(fullpath);
				break;
			}
			// do not overwrite ret with OK if it previously
			// had ENTRIES_REMAINING
			if(r==RECDEL_ENTRIES_REMAINING) ret=r;
		}
		else if(delfiles)
		{
			if(unlink(fullpath))
			{
				logp("unlink %s: %s\n",
					fullpath, strerror(errno));
				ret=RECDEL_ENTRIES_REMAINING;
			}
		}
		else
		{
			ret=RECDEL_ENTRIES_REMAINING;
		}
		free(fullpath);
		free(dir[n]);
	}
	if(n>0)
	{
		ret=RECDEL_ERROR;
		for(; n>0; n--) free(dir[n]);
	}
	free(dir);

	if(ret==RECDEL_OK && rmdir(directory))
	{
		logp("rmdir %s: %s\n", directory, strerror(errno));
		ret=RECDEL_ERROR;
	}
	free(directory);
	return ret;
}

int read_timestamp(const char *path, char buf[], size_t len)
{
	FILE *fp=NULL;
	char *cp=NULL;

	//if(!(fp=open_file(path, "rb")))
	// avoid alarming message
	if(!(fp=fopen(path, "rb")))
	{
		*buf=0;
		return -1;
	}
	fgets(buf, len, fp);
	fclose(fp);
	if((cp=strrchr(buf, '\n'))) *cp='\0';
	if(!*buf) return -1;
	return 0;
}

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

static int get_link(const char *basedir, const char *lnk, char real[], size_t r)
{
	int len=0;
	char *tmp=NULL;
	if(!(tmp=prepend_s(basedir, lnk, strlen(lnk))))
	{
		log_out_of_memory(__FUNCTION__);
		return -1;
	}
	if((len=readlink(tmp, real, r-1))<0) len=0;
	real[len]='\0';
	free(tmp);
	return 0;
}

int get_current_backups(const char *basedir, struct bu **arr, int *a, int log)
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
	if(get_link(basedir, "working", realwork, sizeof(realwork))
	  || get_link(basedir, "finishing", realfinishing, sizeof(realfinishing)))
			return -1;
	if(!(d=opendir(basedir)))
	{
		if(log) log_and_send("could not open backup directory");
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

		if(dp->d_ino==0
		  || !strcmp(dp->d_name, ".")
		  || !strcmp(dp->d_name, "..")
		  || !strcmp(dp->d_name, realwork)
		  || !strcmp(dp->d_name, realfinishing))
			continue;
		if(!(fullpath=prepend_s(basedir,
			dp->d_name, strlen(dp->d_name)))
		 || !(timestamp=prepend_s(fullpath,
			"timestamp", strlen("timestamp")))
		 || !(hlinkedpath=prepend_s(fullpath,
			"hardlinked", strlen("hardlinked"))))
		{
			ret=-1;
			if(timestamp) free(timestamp);
			if(fullpath) free(fullpath);
			break;
		}
		if((!lstat(fullpath, &statp) && !S_ISDIR(statp.st_mode))
		  || lstat(timestamp, &statp) || !S_ISREG(statp.st_mode)
		  || read_timestamp(timestamp, buf, sizeof(buf))
		  || !(timestampstr=strdup(buf)))
		{
			free(fullpath);
			free(timestamp);
			free(hlinkedpath);
			continue;
		}
		free(timestamp);

		if(!lstat(hlinkedpath, &statp)) hardlinked++;

		if(!(*arr=(struct bu *)realloc(*arr,(i+1)*sizeof(struct bu)))
		  || !((*arr)[i].data=prepend_s(fullpath, "data", strlen("data")))
		  || !((*arr)[i].delta=prepend_s(fullpath, "deltas.reverse", strlen("deltas.reverse"))))
		{
			if(log) log_and_send_oom(__FUNCTION__);
			free(timestampstr);
			free(fullpath);
			free(hlinkedpath);
			break;
		}
		(*arr)[i].path=fullpath;
		(*arr)[i].timestamp=timestampstr;
		(*arr)[i].hardlinked=hardlinked;
		(*arr)[i].deletable=0;
		(*arr)[i].index=strtoul(timestampstr, NULL, 10);
		(*arr)[i].trindex=0;
		i++;
	}
	closedir(d);

	if(*arr) qsort(*arr, i, sizeof(struct bu), bu_cmp);

	if(i>1)
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

int get_new_timestamp(struct config *cconf, const char *basedir, char *buf, size_t s)
{
	int a=0;
	time_t t=0;
	const struct tm *ctm=NULL;
	unsigned long index=0;
	char tmpbuf[32]="";
	struct bu *arr=NULL;

	// Want to prefix the timestamp with an index that increases by
	// one each time. This makes it far more obvious which backup depends
	// on which - even if the system clock moved around. Take that,
	// bacula!

	// get_current_backups orders the array with the highest index number 
	// last
	if(get_current_backups(basedir, &arr, &a, 1)) return -1;
	if(a) index=arr[a-1].index;

	free_current_backups(&arr, a);

	time(&t);
	ctm=localtime(&t);
        // Windows does not like the %T strftime format option - you get
        // complaints under gdb.
	strftime(tmpbuf, sizeof(tmpbuf), cconf->timestamp_format, ctm);
	snprintf(buf, s, "%07lu %s", ++index, tmpbuf);

	return 0;
}

int write_timestamp(const char *timestamp, const char *tstmp)
{
	FILE *fp=NULL;
	if(!(fp=open_file(timestamp, "wb"))) return -1;
	fprintf(fp, "%s\n", tstmp);
	fclose(fp);
	return 0;
}

static int compress(const char *src, const char *dst, struct config *cconf)
{
	int res;
	int got;
	FILE *mp=NULL;
	gzFile zp=NULL;
	char buf[ZCHUNK];

	if(!(mp=open_file(src, "rb"))
	  || !(zp=gzopen_file(dst, comp_level(cconf))))
	{
		close_fp(&mp);
		gzclose_fp(&zp);
		return -1;
	}
	while((got=fread(buf, 1, sizeof(buf), mp))>0)
	{
		res=gzwrite(zp, buf, got);
		if(res!=got)
		{
			logp("compressing manifest - read %d but wrote %d\n",
				got, res);
			close_fp(&mp);
			gzclose_fp(&zp);
			return -1;
		}
	}
	close_fp(&mp);
	return gzclose_fp(&zp); // this can give an error when out of space
}

int compress_file(const char *src, const char *dst, struct config *cconf)
{
	char *dsttmp=NULL;
	pid_t pid=getpid();
	char p[12]="";
	snprintf(p, sizeof(p), "%d", (int)pid);

	if(!(dsttmp=prepend(dst, p, strlen(p), 0 /* no slash */)))
		return -1;
	
	// Need to compress the log.
	logp("Compressing %s to %s...\n", src, dst);
	if(compress(src, dsttmp, cconf)
	  || do_rename(dsttmp, dst))
	{
		unlink(dsttmp);
		free(dsttmp);
		return -1;
	}
	// succeeded - get rid of the uncompressed version
	unlink(src);
	free(dsttmp);
	return 0;
}

int compress_filename(const char *d, const char *file, const char *zfile, struct config *cconf)
{
	char *fullfile=NULL;
	char *fullzfile=NULL;
	if(!(fullfile=prepend_s(d, file, strlen(file)))
	  || !(fullzfile=prepend_s(d, zfile, strlen(zfile)))
	  || compress_file(fullfile, fullzfile, cconf))
	{
		if(fullfile) free(fullfile);
		if(fullzfile) free(fullzfile);
		return -1;
	}
	return 0;
}

static int delete_backup(const char *basedir, struct bu *arr, int a, int b, const char *client)
{
	char *deleteme=NULL;

	logp("deleting %s backup %lu\n", client, arr[b].index);

	if(!(deleteme=prepend_s(basedir, "deleteme", strlen("deleteme")))
	  || do_rename(arr[b].path, deleteme)
	  || recursive_delete(deleteme, NULL, TRUE))
	{
		logp("Error when trying to delete %s\n", arr[b].path);
		free(deleteme);
		return -1;
	}
	free(deleteme);

	return 0;
}

int do_remove_old_backups(const char *basedir, struct config *cconf, const char *client)
{
	int a=0;
	int b=0;
        int x=0;
	int ret=0;
	int deleted=0;
	unsigned long m=1;
	struct bu *arr=NULL;
	struct strlist **kplist=NULL;

	kplist=cconf->keep;

	if(get_current_backups(basedir, &arr, &a, 1)) return -1;

	// For each of the 'keep' values, generate ranges in which to keep
	// one backup.
        for(x=0; x<cconf->kpcount; x++)
        {
		unsigned long n=0;
		n=m * kplist[x]->flag;

                //printf("keep[%d]: %d - m:%lu n:%lu\n",
		//	x, cconf->keep[x]->flag, m, n);
		if(x+1 < cconf->kpcount)
		{
			unsigned long r=0;
			unsigned long s=0;
			unsigned long upto=0;
			upto=n*cconf->keep[x+1]->flag;
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
					if(delete_backup(basedir, arr,
						a, b, client))
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
			if(delete_backup(basedir, arr, a, b, client))
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

int remove_old_backups(const char *basedir, struct config *cconf, const char *client)
{
	int deleted=0;
	// Deleting a backup might mean that more become available to get rid
	// of.
	// Keep trying to delete until we cannot delete any more.
	while(1)
	{
		if((deleted=do_remove_old_backups(basedir, cconf, client))<0)
			return -1;
		else if(!deleted)
			break;
	}
	return 0;
}

/* Need to base librsync block length on the size of the old file, otherwise
   the risk of librsync collisions and silent corruption increases as the
   size of the new file gets bigger. */
size_t get_librsync_block_len(const char *endfile)
{
	size_t ret=0;
	unsigned long long oldlen=0;
	oldlen=strtoull(endfile, NULL, 10);
	ret=(size_t)(ceil(sqrt(oldlen)/16)*16); // round to a multiple of 16.
	if(ret<64) return 64; // minimum of 64 bytes.
	return ret;
}

#define DUP_CHUNK	4096
static int duplicate_file(const char *oldpath, const char *newpath)
{
	int ret=0;
	size_t s=0;
	size_t t=0;
	FILE *op=NULL;
	FILE *np=NULL;
	char buf[DUP_CHUNK]="";
	if(!(op=open_file(oldpath, "rb"))
	  || !(np=open_file(newpath, "wb")))
	{
		ret=-1;
		goto finish;
	}

	while((s=fread(buf, 1, DUP_CHUNK, op))>0)
	{
		t=fwrite(buf, 1, s, np);
		if(t!=s)
		{
			logp("could not write all bytes: %d!=%d\n", s, t);
			ret=-1;
			goto finish;
		}
	}

finish:
	if(np) fclose(np);
	if(op) fclose(op);
	if(ret) logp("could not duplicate %s to %s\n", oldpath, newpath);
	return ret;
}

int do_link(const char *oldpath, const char *newpath, struct stat *statp, struct config *conf, bool overwrite)
{
	/* Avoid creating too many hardlinks */
	if(statp->st_nlink >= (unsigned int)conf->max_hardlinks)
	{
		return duplicate_file(oldpath, newpath);
	}
	else if(link(oldpath, newpath))
	{
		if(overwrite && errno==EEXIST)
		{
			unlink(newpath);
			if(link(oldpath, newpath))
			{
				logp("could not hard link '%s' to '%s': %s\n",
					newpath, oldpath, strerror(errno));
				return -1;
			}
			else
			{
				logp("Successful hard link of '%s' to '%s' after unlinking the former\n", newpath, oldpath);
				return 0;
			}
		}
		return -1;
	}
	return 0;
}
