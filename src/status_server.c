#include "burp.h"
#include "prog.h"
#include "msg.h"
#include "lock.h"
#include "handy.h"
#include "asyncio.h"
#include "counter.h"
#include "sbuf.h"
#include "current_backups_server.h"
#include "status_server.h"
#include "list_client.h"
#include "list_server.h"

struct cstat
{
	char *name;
	char *conffile;
	time_t conf_mtime;
	char *summary;
	char *running_detail; // set from the parent process
	char status;

	// When the mtime of conffile changes, the following get reloaded
	char *basedir;
	time_t basedir_mtime;
	char *working;
	char *current;
	char *timestamp;
	char *lockfile;
	time_t lockfile_mtime;
};

int cstat_sort(const void *a, const void *b)
{
	struct cstat **x=(struct cstat **)a;
	struct cstat **y=(struct cstat **)b;
	if(!x || !y) return 0;
	if(!*x && !*y) return 0;
	if(!*x) return -1;
	if(!*y) return 1;
	if(!(*x)->name) return -1;
	if(!(*y)->name) return 1;
	return strcmp((*x)->name, (*y)->name);
}

static int cstat_add_initial_details(struct cstat *c, const char *name, const char *clientconfdir)
{
	if(!(c->conffile=prepend_s(clientconfdir, name, strlen(name)))
	  || !(c->name=strdup(name)))
	{
		log_out_of_memory(__FUNCTION__);
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
	c->lockfile_mtime=0;
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
		log_out_of_memory(__FUNCTION__);
		return -1;
	}
	*clist=ctmp;
	if(!(cnew=(struct cstat *)malloc(sizeof(struct cstat))))
	{
		log_out_of_memory(__FUNCTION__);
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
	c->basedir_mtime=0;
	c->lockfile_mtime=0;
}

static int set_cstat_from_conf(struct cstat *c, struct config *conf, struct config *cconf)
{
	char *lockbasedir=NULL;
	if(c->basedir) { free(c->basedir); c->basedir=NULL; }
	if(c->working) { free(c->working); c->working=NULL; }
	if(c->current) { free(c->current); c->current=NULL; }
	if(c->timestamp) { free(c->timestamp); c->timestamp=NULL; }

	if(!(c->basedir=prepend_s(cconf->directory, c->name, strlen(c->name)))
	  || !(c->working=prepend_s(c->basedir, "working", strlen("working")))
	  || !(c->current=prepend_s(c->basedir, "current", strlen("current")))
	  || !(c->timestamp=prepend_s(c->current, "timestamp", strlen("timestamp")))
	  || !(lockbasedir=prepend_s(conf->client_lockdir, c->name, strlen(c->name)))
	  || !(c->lockfile=prepend_s(lockbasedir, "lockfile", strlen("lockfile"))))
	{
		if(lockbasedir) free(lockbasedir);
		log_out_of_memory(__FUNCTION__);
		return -1;
	}
	c->basedir_mtime=0;
	c->lockfile_mtime=0;
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

static char *get_last_backup_time(const char *timestamp)
{
	static char ret[64]="";
	char wbuf[64]="";
	snprintf(ret, sizeof(ret), "0");
	if(read_timestamp(timestamp, wbuf, sizeof(wbuf))) return ret;

	snprintf(ret, sizeof(ret), "%lu 0 %li", atol(wbuf),
		(long)timestamp_to_long(wbuf));
	  
	return ret;
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
			c->status=STATUS_IDLE;
			snprintf(wbuf, sizeof(wbuf), "%s\t%c\t%c\t%s\n",
				c->name, COUNTER_VERSION_2, c->status,
				get_last_backup_time(c->timestamp));
		}
		else
		{
			// client process crashed
			c->status=STATUS_CLIENT_CRASHED;
			snprintf(wbuf, sizeof(wbuf), "%s\t%c\t%c\t%s\n",
				c->name, COUNTER_VERSION_2, c->status,
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
		char *prog=NULL;
		if(!test_lock(c->lockfile)) // could have got lock
		{
			//time_t t=0;
			//if(!lstat(c->working, &statp)) t=statp.st_ctime;
			// server process crashed
			c->status=STATUS_SERVER_CRASHED;
			snprintf(wbuf, sizeof(wbuf), "%s\t%c\t%c\t%s\n",
				c->name, COUNTER_VERSION_2, c->status,
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
			// running normally
			c->status=STATUS_RUNNING;
			snprintf(wbuf, sizeof(wbuf), "%s\t%c\t%c\t%s\n",
				c->name, COUNTER_VERSION_2, c->status,
				get_last_backup_time(c->timestamp));
		}
		if(prog) free(prog);
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

	struct dirent **dir=NULL;

	if((n=scandir(conf->clientconfdir, &dir, 0, 0))<0)
	{
		logp("could not scandir clientconfdir: %s\n",
			conf->clientconfdir, strerror(errno));
		return -1;
	}
        for(m=0; m<n; m++)
	{
		if(dir[m]->d_ino==0
		// looks_like...() also avoids '.' and '..'.
		  || looks_like_tmp_or_hidden_file(dir[m]->d_name))
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
	if(dir) free(dir);
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
		// Allow directories to exist in the conf dir.
		if(!S_ISREG(statp.st_mode))
		{
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
		if(set_client_global_config(conf, &cconf, (*clist)[q]->name)
		  || load_config((*clist)[q]->conffile, &cconf, FALSE))
		{
			free_config(&cconf);
			cstat_blank((*clist)[q]);
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
		struct stat lstatp;
		time_t ltime=0;
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
		if(!lstat((*clist)[q]->lockfile, &lstatp))
			ltime=lstatp.st_mtime;
		//logp("pre set summary for %s\n", (*clist)[q]->name);
		if(statp.st_mtime==(*clist)[q]->basedir_mtime
		  && ltime==(*clist)[q]->lockfile_mtime
		  && (*clist)[q]->status!=STATUS_SERVER_CRASHED
		  && !((*clist)[q]->running_detail))
		{
			// basedir has not changed - no need to do anything.
			continue;
		}
		(*clist)[q]->basedir_mtime=statp.st_mtime;
		(*clist)[q]->lockfile_mtime=ltime;

		if(set_summary((*clist)[q]))
		{
			ret=-1;
			break;
		}
	}

	return ret;
}

static int send_data_to_client(int cfd, const char *data, size_t len)
{
	int ret=0;
	const char *w=data;
//printf("need to write: %d\n", len);
	while(len>0)
	{
		ssize_t wl=0;
		int mfd=-1;
		fd_set fsw;
		fd_set fse;
		struct timeval tval;

		FD_ZERO(&fsw);
		FD_ZERO(&fse);

		tval.tv_sec=1;
		tval.tv_usec=0;

		add_fd_to_sets(cfd, NULL, &fsw, &fse, &mfd);

		if(select(mfd+1, NULL, &fsw, &fse, &tval)<0)
		{
			if(errno!=EAGAIN && errno!=EINTR)
			{
				logp("select error in %s: %s\n", __func__,
					strerror(errno));
				ret=-1;
				break;
			}
			continue;
		}

		if(FD_ISSET(cfd, &fse))
		{
			// Client exited?
			logp("exception on client fd when writing\n");
			break;
		}
		if(!FD_ISSET(cfd, &fsw)) continue;

		if((wl=write(cfd, w, len))<=0)
		{
			if(errno==EPIPE)
			{
				ret=-1;
				goto end;
			}
			if(errno!=EINTR)
			{
				logp("error writing in send_data_to_client(): %s\n", strerror(errno));
				ret=-1;
				goto end;
			}
//			printf("got EINTR\n");
		}
		else if(wl>0)
		{
			w+=wl;
			len-=wl;
		}
//		printf("wrote: %d left: %d\n", wl, len);
	}
end:
	return ret;
}

static int send_summaries_to_client(int cfd, struct cstat **clist, int clen, const char *sel_client)
{
	int q=0;

	// If there are no backup clients to list, just give a new line.
	// Without this, the status client will stay in a loop trying to read
	// data when in snapshot mode.
	if(!clen) send_data_to_client(cfd, "\n", 1);

	for(q=0; q<clen; q++)
	{
		const char *tosend=NULL;
		char *curback=NULL;

		// Currently, if you delete a conf file, the entry does not
		// get removed from our list - they get blanked out instead.
		if(!clist[q]->name) continue;

                if(!clist[q]->summary || !*(clist[q]->summary))
		{
			if(set_summary(clist[q]))
				return -1;
		}
                if(clist[q]->running_detail && *(clist[q]->running_detail))
		{
			tosend=clist[q]->running_detail;
		}
		else if(sel_client && !strcmp(sel_client, clist[q]->name)
		  && (clist[q]->status==STATUS_IDLE
			|| clist[q]->status==STATUS_CLIENT_CRASHED
			|| clist[q]->status==STATUS_SERVER_CRASHED))
		{
			// Client not running, but asked for detail.
			// Gather a list of successful backups to talk about.
        		int a=0;
        		struct bu *arr=NULL;
			if(get_current_backups(clist[q]->basedir, &arr, &a, 0))
			{
				//logp("error when looking up current backups\n");
				tosend=clist[q]->summary;
			}
			else if(a>0)
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
					log_out_of_memory(__FUNCTION__);
					return -1;
				}
				snprintf(curback, len, "%s\t%c\t%c",
					clist[q]->name, COUNTER_VERSION_2,
					clist[q]->status);
				for(i=a-1; i>=0; i--)
				{
					char tmp[16]="";
					t=timestamp_to_long(arr[i].timestamp);
					snprintf(tmp, sizeof(tmp), "\t%lu %d %li",
						arr[i].index, arr[i].deletable, (long)t);
					strcat(curback, tmp);
				}
				if(!a) strcat(curback, "\t0");
				strcat(curback, "\n");
        			free_current_backups(&arr, a);

				// Overwrite the summary with it.
				// It will get updated again
				if(clist[q]->summary) free(clist[q]->summary);
				clist[q]->summary=curback;
				tosend=clist[q]->summary;
			}
			else tosend=clist[q]->summary;
		}
		else tosend=clist[q]->summary;

		if(!tosend || !*tosend) tosend="\n";
		//printf("send summary: %s (%s)\n", clist[q]->name, tosend);
		if(send_data_to_client(cfd, tosend, strlen(tosend))) return -1;
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
			if(send_data_to_client(cfd, tosend, strlen(tosend)))
				return -1;
			break;
		}
	}
	return 0;
}
*/


static int parse_parent_data_entry(char *tok, struct cstat **clist, int clen)
{
	int q=0;
	char *tp=NULL;
	//logp("status server got: %s", tok);

	// Find the array entry for this client,
	// and add the detail from the parent to it.
	// The name of the client is at the start, and
	// the fields are tab separated.
	if(!(tp=strchr(tok, '\t'))) return 0;
	*tp='\0';
	for(q=0; q<clen; q++)
	{
		if(clist[q]->name
		  && !strcmp(clist[q]->name, tok))
		{
			int x=0;
			*tp='\t'; // put the tab back.
			x=strlen(tok);
			if(clist[q]->running_detail)
			free(clist[q]->running_detail);
			clist[q]->running_detail=NULL;
			//clist[q]->running_detail=strdup(tok);

			// Need to add the newline back on the end.
			if(!(clist[q]->running_detail=(char *)malloc(x+2)))
			{
				log_out_of_memory(__FUNCTION__);
				return -1;
			}
			snprintf(clist[q]->running_detail, x+2, "%s\n",
				tok);
			
		}
	}
	return 0;
}

static int parse_parent_data(const char *data, struct cstat **clist, int clen)
{
	char *tok=NULL;
	char *copyall=NULL;

	if(!(copyall=strdup(data)))
	{
		log_out_of_memory(__FUNCTION__);
		return -1;
	}

	if((tok=strtok(copyall, "\n")))
	{
		if(parse_parent_data_entry(tok, clist, clen))
		{
			free(copyall);
			return -1;
		}
		while((tok=strtok(NULL, "\n")))
		{
			if(parse_parent_data_entry(tok, clist, clen))
			{
				free(copyall);
				return -1;
			}
		}
	}

	free(copyall);
	return 0;
}

static cstat *get_cstat_by_client_name(struct cstat **clist, int clen, const char *client)
{
	int c=0;
	for(c=0; c<clen; c++)
	{
		if(clist[c]->name && !strcmp(clist[c]->name, client))
			return clist[c];
	}
	return NULL;
}

static int list_backup_file_name(int cfd, const char *dir, const char *file)
{
	int ret=0;
	char *path=NULL;
	char msg[256]="";
	struct stat statp;
	if(!(path=prepend_s(dir, file, strlen(file))))
		return -1;
	if(lstat(path, &statp) || !S_ISREG(statp.st_mode))
	{
		free(path);
		return 0;
	}
	snprintf(msg, sizeof(msg), "%s\n", file);
	ret=send_data_to_client(cfd, msg, strlen(msg));
	free(path);
	return ret;
}

static int browse_manifest(int cfd, gzFile zp, const char *browse)
{
	int ars=0;
	int ret=0;
	char ls[1024]="";
	struct sbuf sb;
	struct cntr cntr;
	size_t blen=0;
	reset_filecounter(&cntr, time(NULL));
	init_sbuf(&sb);
	if(browse) blen=strlen(browse);
	while(1)
	{
		int r;
		free_sbuf(&sb);
		if((ars=sbuf_fill(NULL, zp, &sb, &cntr)))
		{
			if(ars<0) ret=-1;
			// ars==1 means it ended ok.
			break;
		}

		if(sb.cmd!=CMD_DIRECTORY
		  && sb.cmd!=CMD_FILE
		  && sb.cmd!=CMD_ENC_FILE
		  && sb.cmd!=CMD_EFS_FILE
		  && sb.cmd!=CMD_SPECIAL
		  && !cmd_is_link(sb.cmd))
			continue;

		if((r=check_browsedir(browse, &sb.path, blen))<0)
		{
			ret=-1;
			break;
		}
		if(!r) continue;

		ls_output(ls, sb.path, &(sb.statp));

		if(send_data_to_client(cfd, ls, strlen(ls))
		  || send_data_to_client(cfd, "\n", 1))
		{
			ret=-1;
			break;
		}
	}
	free_sbuf(&sb);
	return ret;
}

static int list_backup_file_contents(int cfd, const char *dir, const char *file, const char *browse)
{
	int ret=0;
	size_t l=0;
	gzFile zp=NULL;
	char *path=NULL;
	char buf[256]="";
	if(!(path=prepend_s(dir, file, strlen(file))))
		return -1;
	if(!(zp=gzopen_file(path, "rb")))
	{
		free(path);
		return -1;
	}

	if(send_data_to_client(cfd, "-list begin-\n", strlen("-list begin-\n")))
	{
		ret=-1;
		goto end;
	}

	if(!strcmp(file, "manifest.gz"))
	{
		ret=browse_manifest(cfd, zp, browse?:"");
	}
	else
	{
		while((l=gzread(zp, buf, sizeof(buf)))>0)
		{
			if(send_data_to_client(cfd, buf, l))
			{
				ret=-1;
				break;
			}
		}
	}
	if(send_data_to_client(cfd, "-list end-\n", strlen("-list end-\n")))
	{
		ret=-1;
		goto end;
	}
end:
	gzclose_fp(&zp);
	return ret;
}

static int list_backup_dir(int cfd, struct cstat *cli, unsigned long bno)
{
        int a=0;
	int ret=0;
        struct bu *arr=NULL;
	if(get_current_backups(cli->basedir, &arr, &a, 0))
	{
		//logp("error when looking up current backups\n");
		return -1;
	}
	if(a>0)
	{
		int i=0;
		for(i=0; i<a; i++) if(arr[i].index==bno) break;
		if(i<a)
		{
			if(send_data_to_client(cfd, "-list begin-\n",
				strlen("-list begin-\n")))
			{
				ret=-1;
				goto end;
			}
			list_backup_file_name(cfd,arr[i].path, "manifest.gz");
			list_backup_file_name(cfd,arr[i].path, "log.gz");
			list_backup_file_name(cfd,arr[i].path, "restorelog.gz");
			list_backup_file_name(cfd,arr[i].path, "verifylog.gz");
			if(send_data_to_client(cfd, "-list end-\n",
				strlen("-list end-\n")))
			{
				ret=-1;
				goto end;
			}
		}
	}
end:
	if(a>0) free_current_backups(&arr, a);
	return ret;
}

static int list_backup_file(int cfd, struct cstat *cli, unsigned long bno, const char *file, const char *browse)
{
        int a=0;
        struct bu *arr=NULL;
	if(get_current_backups(cli->basedir, &arr, &a, 0))
	{
		//logp("error when looking up current backups\n");
		return -1;
	}
	if(a>0)
	{
		int i=0;
		for(i=0; i<a; i++) if(arr[i].index==bno) break;
		if(i<a)
		{
			printf("found: %s\n", arr[i].path);
			list_backup_file_contents(cfd, arr[i].path,
				file, browse);
		}
		free_current_backups(&arr, a);
	}
	return 0;
}

static char *get_str(const char **buf, const char *pre, int last)
{
	size_t len=0;
	char *cp=NULL;
	char *copy=NULL;
	char *ret=NULL;
	if(!buf || !*buf) return NULL;
	len=strlen(pre);
	if(strncmp(*buf, pre, len)) return NULL;
	if(!(copy=strdup((*buf)+len))) return NULL;
	if(!last && (cp=strchr(copy, ':'))) *cp='\0';
	*buf+=len+strlen(copy)+1;
	ret=strdup(copy);
	free(copy);
	return ret;
}

static int parse_rbuf(const char *rbuf, int cfd, struct cstat **clist, int clen)
{
	int ret=0;
	const char *cp=NULL;
	char *client=NULL;
	char *backup=NULL;
	char *file=NULL;
	char *browse=NULL;
	unsigned long bno=0;
	struct cstat *cli=NULL;

	cp=rbuf;
	client=get_str(&cp, "c:", 0);
	backup=get_str(&cp, "b:", 0);
	file  =get_str(&cp, "f:", 0);
	browse=get_str(&cp, "p:", 1);
	if(browse)
	{
		if(file) free(file);
		if(!(file=strdup("manifest.gz")))
		{
			log_out_of_memory(__FUNCTION__);
			ret=-1;
			goto end;
		}
		// Strip trailing slashes.
		if(strlen(browse)>1 && browse[strlen(browse)-1]=='/')
			browse[strlen(browse)-1]='\0';
	}

	if(client)
	{
		if(!(cli=get_cstat_by_client_name(clist, clen, client)))
			goto end;
	}
	if(backup)
	{
		if(!(bno=strtoul(backup, NULL, 10)))
			goto end;
	}
	if(file)
	{
		if(strcmp(file, "manifest.gz")
		  && strcmp(file, "log.gz")
		  && strcmp(file, "restorelog.gz")
		  && strcmp(file, "verifylog.gz"))
			goto end;
	}
/*
	printf("client: %s\n", client?:"");
	printf("backup: %s\n", backup?:"");
	printf("file: %s\n", file?:"");
*/
	if(client)
	{
		if(bno)
		{
			if(file || browse)
			{
			  printf("list file %s of backup %lu of client '%s'\n",
			    file, bno, client);
			  if(browse) printf("browse '%s'\n", browse);
				list_backup_file(cfd, cli, bno, file, browse);
			}
			else
			{
				printf("list backup %lu of client '%s'\n",
					bno, client);
				printf("basedir: %s\n", cli->basedir);
				list_backup_dir(cfd, cli, bno);
			}
		}
		else
		{
			//printf("detail request: %s\n", rbuf);
			if(send_summaries_to_client(cfd, clist, clen, client))
			{
				ret=-1;
				goto end;
			}
		}
	}
	else
	{
		//printf("summaries request\n");
		if(send_summaries_to_client(cfd, clist, clen, NULL))
		{
			ret=-1;
			goto end;
		}
	}

	// Kludge - exit straight away if doing snapshot type stuff. 
/*
	if(backup || file || browse)
	{
		ret=-1;
		goto end;
	}
*/
end:
	if(client) free(client);
	if(backup) free(backup);
	if(file) free(file);
	if(browse) free(browse);
	return ret;
}

/* Incoming status request */
int status_server(int *cfd, struct config *conf)
{
	int l;
	int ret=0;
	char *rbuf=NULL;
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
				logp("select error in %s: %s\n", __func__,
					strerror(errno));
				ret=-1;
				break;
			}
			continue;
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

			if(parse_parent_data(buf, clist, clen))
			{
				ret=-1;
				break;
			}
	//		continue;
		}

		if(FD_ISSET(*cfd, &fsr))
		{
			char *cp=NULL;
			ssize_t total=0;
			//logp("status server stuff to read from client\n");
			while((l=read(*cfd, buf, sizeof(buf)))>0)
			{
				size_t r=0;
				buf[l]='\0';
				if(rbuf) r=strlen(buf);
				rbuf=(char *)realloc(rbuf, r+l+1);
				if(!r) *rbuf='\0';
				strcat(rbuf+r, buf);
				total+=l;
			}
			if(!total)
			{
				// client went away?
				if(rbuf)
				{
					free(rbuf);
					rbuf=NULL;
				}
				break;
			}
			// If we did not get a full read, do
			// not worry, just throw it away.
			if(rbuf && (cp=strrchr(rbuf, '\n')))
			{
				*cp='\0';
				// Also get rid of '\r'. I think telnet adds
				// this.
				if((cp=strrchr(rbuf, '\r'))) *cp='\0';

				if(parse_rbuf(rbuf, *cfd, clist, clen))
				{
					ret=-1;
					free(rbuf);
					rbuf=NULL;
					break;
				}
				free(rbuf);
				rbuf=NULL;
				if(send_data_to_client(*cfd, "\n", 1))
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
