#include "burp.h"
#include "prog.h"
#include "msg.h"
#include "lock.h"
#include "handy.h"
#include "asyncio.h"
#include "counter.h"
#include "current_backups_server.h"
#include "status_server.h"

struct chldstat *chlds=NULL;

static time_t get_last_backup_time(const char *timestamp)
{
	time_t t=0;
	char *b=NULL;
	char wbuf[64]="";
	if(!read_timestamp(timestamp, wbuf, sizeof(wbuf))
	  && (b=strchr(wbuf, ' ')))
	{
		struct tm tm;
		memset(&tm, 0, sizeof(struct tm));
		if(strptime(b, " %Y-%m-%d %H:%M:%S", &tm))
		{
			// Tell mktime to use the daylight savings time setting
			// from the time zone of the system.
			tm.tm_isdst=-1;
			t=mktime(&tm);
		}
	}
	return t;
}

static int examine_spool_dir(int cfd, struct config *cconf, const char *client)
{
	char *w=NULL;
	char wbuf[256]="";
	char *basedir=NULL;
	char *working=NULL;
	char *current=NULL;
	char *lockfile=NULL;
	char *timestamp=NULL;
	struct stat statp;

	if(!(basedir=prepend_s(cconf->directory, client, strlen(client)))
	  || !(working=prepend_s(basedir, "working", strlen("working")))
	  || !(current=prepend_s(basedir, "current", strlen("current")))
	  || !(timestamp=prepend_s(current, "timestamp", strlen("timestamp")))
	  || !(lockfile=prepend_s(basedir, "lockfile", strlen("lockfile"))))
	{
		logp("out of memory\n");
		return -1;
	}

	if(lstat(lockfile, &statp))
	{
		if(lstat(working, &statp))
		{
			snprintf(wbuf, sizeof(wbuf), "%s\ti\t%li\n", client,
				get_last_backup_time(timestamp));
		}
		else
		{
			// client process crashed
			snprintf(wbuf, sizeof(wbuf), "%s\tc\t%li\t%li\n",
				client,
				get_last_backup_time(timestamp),
				statp.st_ctime);
		}
	}
	else
	{
		if(!test_lock(lockfile))
		{
			time_t t=0;
			if(!lstat(working, &statp)) t=statp.st_ctime;
			// server process crashed
			snprintf(wbuf, sizeof(wbuf), "%s\tC\t%li\t%li\n",
				client, get_last_backup_time(timestamp), t);
		}
		// else running - this should have got picked up before this
		// function was called.
	}

	if(basedir) free(basedir);
	if(working) free(working);
	if(current) free(current);
	if(lockfile) free(lockfile);
	if(timestamp) free(timestamp);

	w=wbuf;
	while(*w)
	{
		size_t wl=0;
		if((wl=write(cfd, w, strlen(w)))<0)
		{
			if(errno!=EINTR)
			{
				//logp("error writing in examine_spool_dir(): %s\n", strerror(errno));
				return -1;
			}
		}
		w+=wl;
	}
	return 0;
}

static int send_status_info(int cfd, struct config *conf, const char *request)
{
	int q=0;
	int m=0;
	int n=-1;
	int ret=0;
	size_t l=0;
	char *cpath=NULL;

	struct dirent **dir;

	if((n=scandir(conf->clientconfdir, &dir, 0, alphasort))<0)
	{
		logp("could not scandir clientconfdir: %s\n",
			conf->clientconfdir, strerror(errno));
		return -1;
	}
        for(m=0; m<n; m++)
	{
		int found=0;

		if(dir[m]->d_ino==0
		  || !strcmp(dir[m]->d_name, ".")
		  || !strcmp(dir[m]->d_name, ".."))
			{ free(dir[m]); dir[m]=NULL; continue; }

		if(!(cpath=prepend_s(conf->clientconfdir,
			dir[m]->d_name, strlen(dir[m]->d_name))))
		{
			ret=-1;
			break;
		}

		if(*request && strcmp(request, dir[m]->d_name)) continue;

		for(q=0; chlds && chlds[q].pid!=-2; q++)
		{
			if(!chlds[q].name
			  || !chlds[q].data
			  || strcmp(dir[m]->d_name, chlds[q].name)
			  || !(l=strlen(chlds[q].data)))
				continue;

			if(write(cfd, chlds[q].data, l)<0)
			{
				if(errno!=EINTR)
				{
					//logp("send_status_info write error: %s\n", strerror(errno));
					ret=-1;
				}
				break;
			}
			found=1;
			break;
		}
		if(ret)
		{
			if(cpath) { free(cpath); cpath=NULL; }
			break;
		}
		if(!found)
		{
			// It is not running. Grub around trying to find
			// info from the file system.
			char *cpath=NULL;
			struct config cconf;
			init_config(&cconf);
			if(!(cpath=prepend_s(conf->clientconfdir,
				dir[m]->d_name, strlen(dir[m]->d_name)))
			  || set_client_global_config(conf, &cconf)
			  || load_config(cpath, &cconf, 0))
			{
				free_config(&cconf);
				if(cpath) { free(cpath); cpath=NULL; }
				free(dir[m]); dir[m]=NULL;
				continue;
			}
			if(cpath) { free(cpath); cpath=NULL; }
			if(examine_spool_dir(cfd, &cconf, dir[m]->d_name))
			{
				//logp("examine_spool_dir returned error\n");
				ret=-1;
				break;
			}
			free_config(&cconf);
		}

		if(cpath) { free(cpath); cpath=NULL; }
		free(dir[m]); dir[m]=NULL;
	}

	if(cpath) free(cpath);
	for(m=0; m<n; m++) if(dir[m]) free(dir[m]);

	free(dir);

	return ret;
}

/* Incoming status request */
int process_status_client(int fd, struct config *conf)
{
	int l;
	int ret=0;
	int cfd=-1;
	char buf[256]="";
	socklen_t client_length=0;
	struct sockaddr_in client_name;

	client_length=sizeof(client_name);
	if((cfd=accept(fd,
		(struct sockaddr *) &client_name,
		&client_length))==-1)
	{
		// Look out, accept will get interrupted by SIGCHLDs.
		if(errno==EINTR) return 0;
		logp("accept failed: %s\n", strerror(errno));
		return -1;
	}
	reuseaddr(cfd);
	set_blocking(cfd);

	while((l=read(cfd, buf, sizeof(buf)-2))>0)
	{
		// If we did not get a full read, do
		// not worry, just throw it away.
		if(buf[l-1]=='\n')
		{
			buf[l-1]='\0';

			if(send_status_info(cfd, conf, buf))
			{
				//logp("send_status_info returned error\n");
				ret=-1;
				break;
			}
		}
		write(cfd, "\n", 1);
	}
	close_fd(&cfd);
	return ret;
}
