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
#include <regex.h>

int recursive_hardlink(const char *src, const char *dst, const char *client, struct cntr *cntr)
{
	int n=-1;
	int ret=0;
	struct dirent **dir;
	char *tmp=NULL;
	//logp("in rec hl: %s %s\n", src, dst);
	if(!(tmp=prepend_s(dst, "dummy", strlen("dummy"))))
		return -1;
	if(mkpath(&tmp))
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

		if(is_dir(fullpatha))
		{
			if(recursive_hardlink(fullpatha, fullpathb, client, cntr))
			{
				free(fullpatha);
				free(fullpathb);
				break;
			}
		}
		else
		{
			//logp("hardlinking %s to %s\n", fullpathb, fullpatha);
			write_status(client, 4, fullpathb, cntr);
			if(link(fullpatha, fullpathb))
			{
				logp("hardlink %s to %s failed: %s\n",
					fullpathb, fullpatha, strerror(errno));
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
		logp("out of memory\n");
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

		if(is_dir(fullpath))
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
			free((*arr)[b].path);
		if((*arr)[b].data)
			free((*arr)[b].data);
		if((*arr)[b].delta)
			free((*arr)[b].delta);
		if((*arr)[b].timestamp)
			free((*arr)[b].timestamp);
		if((*arr)[b].forward_timestamp)
			free((*arr)[b].forward_timestamp);
	}
	free(*arr);
}

int get_current_backups(const char *basedir, struct bu **arr, int *a)
{
	int i=0;
	int j=0;
	int ret=0;
	DIR *d=NULL;
	char buf[32]="";
	struct dirent *dp=NULL;

	if(!(d=opendir(basedir)))
	{
		log_and_send("could not open backup directory");
		return -1;
	}
	while((dp=readdir(d)))
	{
		struct stat statp;
		char *fullpath=NULL;
		char *timestamp=NULL;
		char *forward=NULL;
		char *timestampstr=NULL;
		char *forward_timestampstr=NULL;

		if(dp->d_ino==0
		  || !strcmp(dp->d_name, ".")
		  || !strcmp(dp->d_name, ".."))
			continue;
		if(!(fullpath=prepend_s(basedir,
			dp->d_name, strlen(dp->d_name)))
		 || !(timestamp=prepend_s(fullpath,
			"timestamp", strlen("timestamp")))
		 || !(forward=prepend_s(fullpath,
			"forward", strlen("forward"))))
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
			free(forward);
			free(timestamp);
			continue;
		}
		free(timestamp);

		if(!read_timestamp(forward, buf, sizeof(buf)))
			forward_timestampstr=strdup(buf);
		free(forward);

		if(!(*arr=(struct bu *)realloc(*arr,(i+1)*sizeof(struct bu)))
		  || !((*arr)[i].data=prepend_s(fullpath, "data", strlen("data")))
		  || !((*arr)[i].delta=prepend_s(fullpath, "deltas.reverse", strlen("deltas.reverse"))))
		{
			log_and_send("out of memory");
			free(timestampstr);
			free(fullpath);
			break;
		}
		(*arr)[i].path=fullpath;
		(*arr)[i].timestamp=timestampstr;
		(*arr)[i].index=strtoul(timestampstr, NULL, 10);
		if(forward_timestampstr)
		{
			(*arr)[i].forward_timestamp=forward_timestampstr;
			(*arr)[i].forward_index=strtoul(forward_timestampstr,
				NULL, 10);
		}
		else
		{
			(*arr)[i].forward_timestamp=NULL;
			(*arr)[i].forward_index=0;
		}
		i++;
	}
	closedir(d);

	if(*arr) qsort(*arr, i, sizeof(struct bu), bu_cmp);

	for(j=0; j<i-1; j++)
	{
		if(!(*arr)[j].forward_timestamp
		  || strcmp((*arr)[j].forward_timestamp, (*arr)[j+1].timestamp)
		  || (*arr)[j].forward_index!=(*arr)[j+1].index)
		{
			char msg[256]="";
			snprintf(msg, sizeof(msg), "%s does not match forward path from %s\n", (*arr)[j+1].path, (*arr)[j].path);
			log_and_send(msg);
			free_current_backups(arr, i);
			ret=-1;
			break;
		}
	}

	*a=i;
		  
	return ret;
}

int get_new_timestamp(const char *basedir, char *buf, size_t s)
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
	if(get_current_backups(basedir, &arr, &a)) return -1;
	if(a) index=arr[a-1].index;

	free_current_backups(&arr, a);

	time(&t);
	ctm=localtime(&t);
        // Windows does not like the %T strftime format option - you get
        // complaints under gdb.
	strftime(tmpbuf, sizeof(tmpbuf), "%Y-%m-%d %H:%M:%S", ctm);
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
	char buf[16000];

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
	gzclose_fp(&zp);
	return 0;
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

int remove_old_backups(const char *basedir, int keep)
{
	int a=0;
	int b=0;
	int ret=0;
	int del=0;
	struct bu *arr=NULL;

	logp("in remove_old_backups\n");

	if(get_current_backups(basedir, &arr, &a)) return -1;

	// Find the cut-off point.
	del=a-keep;

	// Trim from the back so that we do not end up with any
	// directories with broken dependencies.
	for(b=0; b<a; b++)
	{
		if(!ret && b<del)
		{
			logp("keeping %d backups\n", keep);
			logp("deleting %s\n", arr[b].timestamp);
			ret=recursive_delete(arr[b].path, NULL, TRUE);
		}
	}

	free_current_backups(&arr, a);

	return ret;
}

int compile_regex(regex_t **regex, const char *str)
{
	if(str)
	{
		if(!(*regex=(regex_t *)malloc(sizeof(regex_t)))
		  || regcomp(*regex, str, REG_EXTENDED))
		{
			log_and_send("unable to compile regex\n");
			return -1;
		}
	}
	return 0;
}

int check_regex(regex_t *regex, const char *buf)
{
	if(!regex) return 1;
	switch(regexec(regex, buf, 0, NULL, 0))
	{
		case 0: return 1;
		case REG_NOMATCH: return 0;
		default: return 0;
	}
}
