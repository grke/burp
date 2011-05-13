#include "burp.h"
#include "prog.h"
#include "msg.h"
#include "lock.h"
#include "handy.h"
#include "asyncio.h"
#include "counter.h"
#include "current_backups_server.h"
#include "status_server.h"

struct cstat
{
	char *name;
	char *conffile;
	time_t conf_mtime;
	char *summary;
	char *running_detail; // set from the parent process
	char status;

	// When the mtime of conffile changes, the following get reloaded
	int valid_conf;
	char *basedir;
	time_t basedir_mtime;
	char *working;
	char *current;
	char *timestamp;
	char *lockfile;
};

int cstat_sort(const void *a, const void *b)
{
	struct cstat **x=(struct cstat **)a;
	struct cstat **y=(struct cstat **)b;
	if(!x || !y) return 0;
	if(!*x && !*y) return 0;
	if(!*x) return -1;
	if(!*y) return 1;
	return strcmp((*x)->name, (*y)->name);
}

static int cstat_add_initial_details(struct cstat *c, const char *name, const char *clientconfdir)
{
	if(!(c->conffile=prepend_s(clientconfdir, name, strlen(name)))
	  || !(c->name=strdup(name)))
	{
		logp("out of memory in cstat_add_initial_details()\n");
		return -1;
	}
	c->conf_mtime=0;
	c->summary=NULL;
	c->running_detail=NULL;
	c->basedir=NULL;
	c->basedir_mtime=0;
	c->working=NULL;
	c->current=NULL;
	c->timestamp=NULL;
	c->lockfile=NULL;
	c->valid_conf=0;
	return 0;
}

static int cstat_add(struct cstat ***clist, int *clen,
	const char *name, const char *clientconfdir)
{
	int q=0;
	struct cstat *cnew=NULL;
	struct cstat **ctmp=NULL;
	if(!name)
	{
		logp("cstat_add called with NULL name!\n");
		return -1;
	}

	// If there is a blank array entry, use that.
	for(q=0; q<*clen; q++)
	{
		if(!(*clist)[q]->name)
		{
			if(cstat_add_initial_details((*clist)[q],
			  name, clientconfdir))
				return -1;
			else
				return 0;
		}
	}
	// Otherwise, increase the size of the array.

	if(!(ctmp=(struct cstat **)realloc(*clist,
		((*clen)+1)*sizeof(struct cstat *))))
	{
		logp("out of memory in cstat_add()\n");
		return -1;
	}
	*clist=ctmp;
	if(!(cnew=(struct cstat *)malloc(sizeof(struct cstat))))
	{
		logp("out of memory in cstat_add()\n");
		return -1;
	}
	if(cstat_add_initial_details(cnew, name, clientconfdir))
		return -1;
	(*clist)[(*clen)++]=cnew;

	//for(b=0; b<*count; b++)
	//      printf("now: %d %s\n", b, (*clist)[b]->name);
	return 0;
}

static void cstat_blank(struct cstat *c)
{
	if(c->name) { free(c->name); c->name=NULL; }
	if(c->conffile) { free(c->conffile); c->conffile=NULL; }
	if(c->summary) { free(c->summary); c->summary=NULL; }
	if(c->running_detail) { free(c->running_detail); c->running_detail=NULL; }
	if(c->basedir) { free(c->basedir); c->basedir=NULL; }
	if(c->working) { free(c->working); c->working=NULL; }
	if(c->current) { free(c->current); c->current=NULL; }
	if(c->timestamp) { free(c->timestamp); c->timestamp=NULL; }
	if(c->lockfile) { free(c->lockfile); c->lockfile=NULL; }
	c->conf_mtime=0;
	c->valid_conf=0;
	c->basedir_mtime=0;
}

static int set_cstat_from_conf(struct cstat *c, struct config *conf, struct config *cconf)
{
	char *lockbasedir=NULL;
	if(c->basedir) { free(c->basedir); c->basedir=NULL; }
	if(c->working) { free(c->working); c->working=NULL; }
	if(c->current) { free(c->current); c->current=NULL; }
	if(c->timestamp) { free(c->timestamp); c->timestamp=NULL; }
	if(c->lockfile) { free(c->lockfile); c->lockfile=NULL; }

	if(!(c->basedir=prepend_s(cconf->directory, c->name, strlen(c->name)))
	  || !(c->working=prepend_s(c->basedir, "working", strlen("working")))
	  || !(c->current=prepend_s(c->basedir, "current", strlen("current")))
	  || !(c->timestamp=prepend_s(c->current, "timestamp", strlen("timestamp")))
	  || !(lockbasedir=prepend_s(conf->client_lockdir, c->name, strlen(c->name)))
	  || !(c->lockfile=prepend_s(lockbasedir, "lockfile", strlen("lockfile"))))
	{
		if(lockbasedir) free(lockbasedir);
		logp("out of memory\n");
		return -1;
	}
	c->valid_conf=1;
	c->basedir_mtime=0;
	if(lockbasedir) free(lockbasedir);
	return 0;
}

static time_t timestamp_to_long(const char *buf)
{
	struct tm tm;
	const char *b=NULL;
	if(!(b=strchr(buf, ' '))) return 0;
	memset(&tm, 0, sizeof(struct tm));
	if(!strptime(b, " %Y-%m-%d %H:%M:%S", &tm)) return 0;
	// Tell mktime to use the daylight savings time setting
	// from the time zone of the system.
	tm.tm_isdst=-1;
	return mktime(&tm);
}

static time_t get_last_backup_time(const char *timestamp)
{
	char wbuf[64]="";
	if(read_timestamp(timestamp, wbuf, sizeof(wbuf))) return 0;
	  
	return timestamp_to_long(wbuf);;
}

static int set_summary(struct cstat *c)
{
	char wbuf[1024]="";
	struct stat statp;
//logp("in set summary for %s\n", c->name);

	if(lstat(c->lockfile, &statp))
	{
		if(lstat(c->working, &statp))
		{
			c->status='i';
			snprintf(wbuf, sizeof(wbuf), "%s\t%c\t%li\n", c->name,
				c->status,
				get_last_backup_time(c->timestamp));
		}
		else
		{
			// client process crashed
			c->status='c';
			snprintf(wbuf, sizeof(wbuf), "%s\t%c\t%li\n",
				c->name, c->status,
				get_last_backup_time(c->timestamp));
			//	statp.st_ctime);
		}
		// It is not running, so free the running_detail.
		if(c->running_detail)
		{
			free(c->running_detail);
			c->running_detail=NULL;
		}
	}
	else
	{
		if(!test_lock(c->lockfile))
		{
			//time_t t=0;
			//if(!lstat(c->working, &statp)) t=statp.st_ctime;
			// server process crashed
			c->status='C';
			snprintf(wbuf, sizeof(wbuf), "%s\t%c\t%li\n",
				c->name, c->status,
				get_last_backup_time(c->timestamp));
			// It is not running, so free the running_detail.
			if(c->running_detail)
			{
				free(c->running_detail);
				c->running_detail=NULL;
			}
		}
		else
		{
			// it is running
			c->status='r';
			*wbuf='\0';
		}
	}

	if(c->summary) free(c->summary);
	c->summary=strdup(wbuf);

	return 0;
}

static int load_data_from_disk(struct config *conf, struct cstat ***clist, int *clen)
{
	int q=0;
	int m=0;
	int n=-1;
	int ret=0;
	//size_t l=0;
	int newclient=0;

	struct dirent **dir;

	if((n=scandir(conf->clientconfdir, &dir, 0, 0))<0)
	{
		logp("could not scandir clientconfdir: %s\n",
			conf->clientconfdir, strerror(errno));
		return -1;
	}
        for(m=0; m<n; m++)
	{
		if(dir[m]->d_ino==0
		  || !strcmp(dir[m]->d_name, ".")
		  || !strcmp(dir[m]->d_name, ".."))
			continue;
		for(q=0; q<*clen; q++)
		{
			if(!(*clist)[q]->name) continue;
			if(!strcmp(dir[m]->d_name, (*clist)[q]->name))
				break;
		}
		if(q==*clen)
		{
			// We do not have this client yet. Add it.
			newclient++;
			if(cstat_add(clist, clen, dir[m]->d_name,
				conf->clientconfdir))
			{
				ret=-1;
				break;
			}
		}
	}
	for(m=0; m<n; m++) if(dir[m]) free(dir[m]);
	free(dir);
	if(ret) return ret;

	if(newclient)
	{
		//for(q=0; q<*clen; q++)
		//{
		//	logp("%d: %s\n", q, (*clist)[q]->name);
		//}
		qsort(*clist, *clen, sizeof(struct cstat *), cstat_sort);
	}

	for(q=0; q<*clen; q++)
	{
		// Look at the client conf files to see if they have changed,
		// and reload bits and pieces if they have.
		struct stat statp;
		struct config cconf;

		if(!(*clist)[q]->conffile) continue;

		if(stat((*clist)[q]->conffile, &statp))
		{
			// TODO: Need to remove the client from the list.
			cstat_blank((*clist)[q]);
			continue;
		}
		if(statp.st_mtime==(*clist)[q]->conf_mtime)
		{
			// conf file has not changed - no need to do anything.
			continue;
		}
		(*clist)[q]->conf_mtime=statp.st_mtime;

		init_config(&cconf);
		if(set_client_global_config(conf, &cconf)
		  || load_config((*clist)[q]->conffile, &cconf, 0))
		{
			free_config(&cconf);
			(*clist)[q]->valid_conf=0;
			continue;
		}

		if(set_cstat_from_conf((*clist)[q], conf, &cconf))
		{
			free_config(&cconf);
			ret=-1;
			break;
		}

		free_config(&cconf);
	}

	for(q=0; q<*clen; q++)
	{
		// Pretty much the same routine for the basedir,
		// except also reload if we have running_detail.
		struct stat statp;
		if(!(*clist)[q]->basedir) continue;
		if(stat((*clist)[q]->basedir, &statp))
		{
			// no basedir
			if(!(*clist)[q]->summary && set_summary((*clist)[q]))
			{
				ret=-1;
				break;
			}
			continue;
		}
		//logp("pre set summary for %s\n", (*clist)[q]->name);
		if(statp.st_mtime==(*clist)[q]->basedir_mtime
		  && !((*clist)[q]->running_detail))
		{
			// basedir has not changed - no need to do anything.
			continue;
		}
		(*clist)[q]->basedir_mtime=statp.st_mtime;

		if(set_summary((*clist)[q]))
		{
			ret=-1;
			break;
		}
	}

	return ret;
}

static int send_data_to_client(int cfd, const char *data)
{
	const char *w=data;
	while(w && *w)
	{
		size_t wl=0;
		if((wl=write(cfd, w, strlen(w)))<0)
		{
			if(errno!=EINTR)
			{
				//logp("error writing in send_data_to_client(): %s\n", strerror(errno));
				return -1;
			}
		}
		w+=wl;
	}
	return 0;
}

static int send_summaries_to_client(int cfd, struct cstat **clist, int clen, int sel_client)
{
	int q=0;
	for(q=0; q<clen; q++)
	{
		char *tosend=NULL;
		char *curback=NULL;
		if(clist[q]->running_detail) tosend=clist[q]->running_detail;
		else if(sel_client==q
		  && (clist[q]->status=='i' // idle
			|| clist[q]->status=='c' // client crashed 
			|| clist[q]->status=='C')) // server crashed
		{
			// Client not running, but asked for detail.
			// Gather a list of successful backups to talk about.
        		int a=0;
        		struct bu *arr=NULL;
			if(get_current_backups(clist[q]->basedir, &arr, &a, 0))
			{
				logp("error when looking up current backups\n");
				tosend=clist[q]->summary;
			}
			else
			{
				int i=0;
				int len=0;
				time_t t=0;
				// make more than enough room for the message
				len+=strlen(clist[q]->name)+1;
				len+=(a*2)+1;
				len+=(a*16)+1;
				if(!(curback=(char *)malloc(len)))
				{
					logp("out of memory");
					return -1;
				}
				snprintf(curback, len, "%s\t%c",
					clist[q]->name, clist[q]->status);
				for(i=a-1; i>=0; i--)
				{
					char tmp[16]="";
					t=timestamp_to_long(arr[i].timestamp);
					snprintf(tmp, sizeof(tmp), "\t%li", t);
					strcat(curback, tmp);
				}
				strcat(curback, "\n");
        			free_current_backups(&arr, a);

				// Overwrite the summary with it.
				// It will get updated again
				if(clist[q]->summary) free(clist[q]->summary);
				clist[q]->summary=curback;
				tosend=clist[q]->summary;
			}
		}
		else tosend=clist[q]->summary;
		//printf("send summary: %s (%s)\n", clist[q]->name, tosend);
		if(send_data_to_client(cfd, tosend)) return -1;
	}

	return 0;
}
/*
static int send_detail_to_client(int cfd, struct cstat **clist, int clen, const char *name)
{
	int q=0;
	for(q=0; q<clen; q++)
	{
		if(clist[q]->name && !strcmp(clist[q]->name, name))
		{
			char *tosend=NULL;
			if(clist[q]->running_detail)
				tosend=clist[q]->running_detail;
			else
				tosend=clist[q]->summary;
			if(send_data_to_client(cfd, tosend)) return -1;
			break;
		}
	}
	return 0;
}
*/

/* Incoming status request */
int status_server(int *cfd, struct config *conf)
{
	int l;
	int ret=0;
	char buf[512]="";
	int clen=0;
	struct cstat **clist=NULL;

	set_non_blocking(*cfd);
	if(status_rfd>=0) set_non_blocking(status_rfd);

	//logp("in status_server\n");
	//logp("status_rfd: %d\n", status_rfd);

	if(load_data_from_disk(conf, &clist, &clen))
	{
		logp("load_data_from_disk returned error\n");
		ret=-1;
	}
	else while(1)
	{
		// Need to get status information from status_rfd.
		// Need to read from cfd to find out what the client wants,
		// and therefore what status to write back to cfd.

		int mfd=-1;
		fd_set fsr;
		fd_set fse;
		struct timeval tval;

		FD_ZERO(&fsr);
		FD_ZERO(&fse);

		tval.tv_sec=5;
		tval.tv_usec=0;

		add_fd_to_sets(*cfd, &fsr, NULL, &fse, &mfd);
		if(status_rfd>=0)
		  add_fd_to_sets(status_rfd, &fsr, NULL, &fse, &mfd);

		if(select(mfd+1, &fsr, NULL, &fse, &tval)<0)
		{
			if(errno!=EAGAIN && errno!=EINTR)
			{
				logp("select error: %s\n", strerror(errno));
				ret=-1;
				break;
			}
		}

		if(status_rfd>=0 && FD_ISSET(status_rfd, &fse))
		{
			// Parent exited?
			logp("exception on read fd\n");
			break;
		}

		if(FD_ISSET(*cfd, &fse))
		{
			// Client exited?
			logp("exception on client fd\n");
			break;
		}

		if(status_rfd>=0 && FD_ISSET(status_rfd, &fsr))
		{
			// Stuff to read.
			//logp("status server stuff to read from parent\n");
			if((l=read(status_rfd, buf, sizeof(buf)-2))<0)
			{
				logp("read error in status_server: %s\n",
					strerror(errno));
				ret=-1;
				break;
			}
			else if(!l)
			{
				// parent went away
				break;
			}
			buf[l]='\0';

			// If we did not get a full read, do
			// not worry, just throw it away.
			if(buf[l-1]=='\n')
			{
				int q=0;
				char *tp=NULL;
				//buf[l-1]='\0';
				//logp("status server got: %s", buf);

				// Find the array entry for this client,
				// and add the detail from the parent to it.
				// The name of the client is at the start, and
				// the fields are tab separated.
				if(!(tp=strchr(buf, '\t'))) continue;
				*tp='\0';
				for(q=0; q<clen; q++)
				{
				  if(clist[q]->name
					&& !strcmp(clist[q]->name, buf))
				  {
					*tp='\t'; // put the tab back.
					if(clist[q]->running_detail)
						free(clist[q]->running_detail);
					clist[q]->running_detail=strdup(buf);
				  }
				}
			}
	//		continue;
		}

		if(FD_ISSET(*cfd, &fsr))
		{
			//logp("status server stuff to read from client\n");
			if((l=read(*cfd, buf, sizeof(buf)-2))<0)
			{
				logp("read error\n");
				ret=-1;
				break;
			}
			else if(!l)
			{
				// client went away
				break;
			}
			// If we did not get a full read, do
			// not worry, just throw it away.
			if(buf[l-1]=='\n')
			{
				buf[l-1]='\0';
				if(!*buf)
				{
					//printf("summaries request\n");
					if(send_summaries_to_client(*cfd,
						clist, clen, -1))
					{
						ret=-1;
						break;
					}
				}
				else
				{
					//printf("detail request: %s\n", buf);
					if(send_summaries_to_client(*cfd,
						clist, clen, atoi(buf)))
					{
						ret=-1;
						break;
					}
				}
				if(send_data_to_client(*cfd, "\n"))
					return -1;
			}
	//		continue;
		}

		// Getting here means that the select timed out.
		// Take the opportunity to reload the client information
		// that we can get from the disk.

		if(load_data_from_disk(conf, &clist, &clen))
		{
			ret=-1;
			break;
		}
	}

	close_fd(cfd);
	return ret;
}
