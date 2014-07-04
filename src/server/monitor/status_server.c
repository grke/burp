#include "include.h"

#include <dirent.h>

// FIX THIS: should probably use struct sdirs.
// And should maybe use a linked list instead of a stupid array.
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
	if(!(c->conffile=prepend_s(clientconfdir, name))
	  || !(c->name=strdup_w(name, __func__)))
		return -1;
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

	if(!(ctmp=(struct cstat **)realloc_w(*clist,
		((*clen)+1)*sizeof(struct cstat *), __func__)))
			return -1;
	*clist=ctmp;
	if(!(cnew=(struct cstat *)malloc(sizeof(struct cstat))))
	{
		log_out_of_memory(__func__);
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
	free_w(&c->name);
	free_w(&c->conffile);
	free_w(&c->summary);
	free_w(&c->running_detail);
	free_w(&c->basedir);
	free_w(&c->working);
	free_w(&c->current);
	free_w(&c->timestamp);
	free_w(&c->lockfile);
	c->conf_mtime=0;
	c->basedir_mtime=0;
	c->lockfile_mtime=0;
}

static int set_cstat_from_conf(struct cstat *c, struct conf *conf, struct conf *cconf)
{
	char *lockbasedir=NULL;
	char *client_lockdir=NULL;

	if(!(client_lockdir=conf->client_lockdir))
		client_lockdir=cconf->directory;

	free_w(&c->basedir);
	free_w(&c->working);
	free_w(&c->current);
	free_w(&c->timestamp);

	if(!(c->basedir=prepend_s(cconf->directory, c->name))
	  || !(c->working=prepend_s(c->basedir, "working"))
	  || !(c->current=prepend_s(c->basedir, "current"))
	  || !(c->timestamp=prepend_s(c->current, "timestamp"))
	  || !(lockbasedir=prepend_s(client_lockdir, c->name))
	  || !(c->lockfile=prepend_s(lockbasedir, "lockfile")))
	{
		free_w(&lockbasedir);
		log_out_of_memory(__func__);
		return -1;
	}
	c->basedir_mtime=0;
	c->lockfile_mtime=0;
	free_w(&lockbasedir);
	return 0;
}

static long timestamp_to_long(const char *buf)
{
	struct tm tm;
	const char *b=NULL;
	if(!(b=strchr(buf, ' '))) return 0;
	memset(&tm, 0, sizeof(struct tm));
	if(!strptime(b, " %Y-%m-%d %H:%M:%S", &tm)) return 0;
	// Tell mktime to use the daylight savings time setting
	// from the time zone of the system.
	tm.tm_isdst=-1;
	return (long)mktime(&tm);
}

#define B_TEMPLATE_MAX	128

static const char *backup_template=
		"   [\n"
		"    \"number\": \"%lu\",\n"
		"    \"deletable\": \"%d\",\n"
		"    \"timestamp\": \"%li\"\n"
		"   ]";

static void fill_backup_template(char *wbuf,
	long number, int deletable, const char *timestamp)
{
	snprintf(wbuf, B_TEMPLATE_MAX, backup_template,
		number, deletable, (long)timestamp_to_long(timestamp));
}

static char *get_last_backup_time(const char *timestamp)
{
	static char ret[B_TEMPLATE_MAX]="";
	char wbuf[64]="[]";
	if(timestamp_read(timestamp, wbuf, sizeof(wbuf))) return ret;
	fill_backup_template(ret, atol(wbuf), 0, wbuf);

	return ret;
}

#define CLI_TEMPLATE_MAX	1024
static const char *client_template=
		"  {\n"
		"   \"name\": \"%s\",\n"
		"   \"status\": \"%s\",\n"
		"   \"backups\":\n"
		"%s\n"
		"  }";

static void fill_wbuf(char *wbuf, struct cstat *c, const char *status)
{
	snprintf(wbuf, CLI_TEMPLATE_MAX, client_template,
		c->name, status, get_last_backup_time(c->timestamp));
}

static int set_summary(struct cstat *c)
{
	char wbuf[CLI_TEMPLATE_MAX]="";
	struct stat statp;
//logp("in set summary for %s\n", c->name);

	if(lstat(c->lockfile, &statp))
	{
		if(lstat(c->working, &statp))
		{
			c->status=STATUS_IDLE;
			fill_wbuf(wbuf, c, "idle");
		}
		else
		{
			// client process crashed
			c->status=STATUS_CLIENT_CRASHED;
			fill_wbuf(wbuf, c, "client_crashed");
		}
		// It is not running, so free the running_detail.
		free_w(&c->running_detail);
	}
	else
	{
		char *prog=NULL;
		if(!lock_test(c->lockfile)) // could have got lock
		{
			// server process crashed
			c->status=STATUS_SERVER_CRASHED;
			fill_wbuf(wbuf, c, "server crashed");
			// It is not running, so free the running_detail.
			free_w(&c->running_detail);
		}
		else
		{
			// running normally
			c->status=STATUS_RUNNING;
			fill_wbuf(wbuf, c, "running");
		}
		free_w(&prog);
	}

	free_w(&c->summary);
	if(!(c->summary=strdup_w(wbuf, __func__))) return -1;

	return 0;
}

static int get_client_names(struct conf *conf,
	struct cstat ***clist, int *clen)
{
	int q=0;
	int m=0;
	int n=-1;
	int newclient=0;

	struct dirent **dir=NULL;

	if((n=scandir(conf->clientconfdir, &dir, 0, 0))<0)
	{
		logp("could not scandir clientconfdir: %s\n",
			conf->clientconfdir, strerror(errno));
		goto error;
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
				conf->clientconfdir)) goto error;
		}
	}
	for(m=0; m<n; m++) free_v((void **)&dir[m]);
	free_v((void **)&dir);

	if(newclient) qsort(*clist, *clen, sizeof(struct cstat *), cstat_sort);

	return 0;
error:
	return -1;
}

static int reload_from_client_confs(struct conf *conf,
	struct cstat ***clist, int *clen)
{
	int q;
	static struct conf *cconf=NULL;

	if(!cconf && !(cconf=conf_alloc())) goto error;

	for(q=0; q<*clen; q++)
	{
		// Look at the client conf files to see if they have changed,
		// and reload bits and pieces if they have.
		struct stat statp;

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

		conf_free_content(cconf);
		if(!(cconf->cname=strdup((*clist)[q]->name)))
		{
			log_out_of_memory(__func__);
			goto error;
		}
		if(conf_set_client_global(conf, cconf)
		  || conf_load((*clist)[q]->conffile, cconf, 0))
		{
			cstat_blank((*clist)[q]);
			continue;
		}

		if(set_cstat_from_conf((*clist)[q], conf, cconf))
			goto error;
	}
	return 0;
error:
	conf_free(cconf);
	cconf=NULL;
	return -1;
}

static int reload_from_basedir(struct conf *conf,
	struct cstat ***clist, int *clen)
{
	int q;
	for(q=0; q<*clen; q++)
	{
		// Pretty much the same routine for the basedir,
		// except also reload if we have running_detail.
		time_t ltime=0;
		struct stat statp;
		struct stat lstatp;
		if(!(*clist)[q]->basedir) continue;
		if(stat((*clist)[q]->basedir, &statp))
		{
			// no basedir
			if(!(*clist)[q]->summary && set_summary((*clist)[q]))
				goto error;
			continue;
		}
		if(!lstat((*clist)[q]->lockfile, &lstatp))
			ltime=lstatp.st_mtime;
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

		if(set_summary((*clist)[q])) goto error;
	}
	return 0;
error:
	return -1;
}

static int load_data_from_disk(struct cstat ***clist,
	int *clen, struct conf *conf)
{
	return get_client_names(conf, clist, clen)
	  || reload_from_client_confs(conf, clist, clen)
	  || reload_from_basedir(conf, clist, clen);
}

static int send_data_to_client(struct asfd *asfd, const char *data, size_t len)
{
	if(asfd->write_strn(asfd, CMD_GEN, data, len)) return -1;
	return 0;
}

static const char *clients_start=
		"{\n"
		" \"clients\":\n"
		" [\n";
static const char *clients_end=
		"\n"
		" ]\n"
		"}\n";

static int send_summaries_to_client(struct asfd *srfd,
	struct cstat **clist, int clen, const char *sel_client)
{
	int q=0;
	int ret=-1;
	int count=0;

	if(send_data_to_client(srfd, clients_start, strlen(clients_start)))
		return -1;

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
				goto end;
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
        		struct bu *bu_list=NULL;

			// FIX THIS: If this stuff used sdirs, there would
			// be no need for a separate bu_list_get_str function.
			if(bu_list_get_str(clist[q]->basedir, &bu_list, 0))
			{
				//logp("error when looking up current backups\n");
				tosend=clist[q]->summary;
			}
			else if(bu_list)
			{
        			int a=1;
				int len=0;
				struct bu *bu;

				// Find the end of the list.
				for(bu=bu_list; bu && bu->next; bu=bu->next)
					a++;

				// make more than enough room for the message
				len+=strlen(clist[q]->name)+1;
				len+=(a*2)+1;
				len+=(a*32)+1;
				len+=1024; // HACK.
				if(!(curback=(char *)malloc_w(len, __func__)))
					goto end;
				fill_wbuf(curback, clist[q], "saadffs");

				// Work backwards.
				for(; bu; bu=bu->prev)
				{
					char tmp[B_TEMPLATE_MAX]="";
					if(bu->next) strcat(curback, ",  \n");
					fill_backup_template(tmp,
						bu->bno,
						bu->deletable,
						bu->timestamp);
					strcat(curback, tmp);
				}
        			bu_list_free(&bu_list);

				// Overwrite the summary with it.
				// It will get updated again
				free_w(&(clist[q]->summary));
				clist[q]->summary=curback;
				tosend=clist[q]->summary;
			}
			else tosend=clist[q]->summary;
		}
		else tosend=clist[q]->summary;

		if(count
		  && send_data_to_client(srfd, ",\n", strlen(",\n")))
			goto end;
		if(send_data_to_client(srfd, tosend, strlen(tosend)))
			goto end;
		count++;
	}

	ret=0;
end:
	send_data_to_client(srfd, clients_end, strlen(clients_end));
	return ret;
}
/*
static int send_detail_to_client(struct asfd *srfd, struct cstat **clist, int clen, const char *name)
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
			if(send_data_to_client(srfd, tosend, strlen(tosend)))
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
			free_w(&(clist[q]->running_detail));
			clist[q]->running_detail=NULL;
			//clist[q]->running_detail=strdup(tok);

			// Need to add the newline back on the end.
			if(!(clist[q]->running_detail=(char *)malloc(x+2)))
			{
				log_out_of_memory(__func__);
				return -1;
			}
			snprintf(clist[q]->running_detail, x+2, "%s\n",
				tok);
			
		}
	}
	return 0;
}

static int parse_parent_data(struct asfd *asfd, struct cstat **clist, int clen)
{
	int ret=-1;
	char *tok=NULL;
	char *copyall=NULL;
printf("got parent data: '%s'\n", asfd->rbuf->buf);

	if(!(copyall=strdup_w(asfd->rbuf->buf, __func__)))
		goto end;

	if((tok=strtok(copyall, "\n")))
	{
printf("got tok: %s\n", tok);
		if(parse_parent_data_entry(tok, clist, clen)) goto end;
		while((tok=strtok(NULL, "\n")))
			if(parse_parent_data_entry(tok, clist, clen))
				goto end;
	}

	ret=0;
end:
	free_w(&copyall);
	return ret;
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

static int list_backup_file_name(struct asfd *srfd, const char *dir, const char *file)
{
	int ret=0;
	char *path=NULL;
	char msg[256]="";
	struct stat statp;
	if(!(path=prepend_s(dir, file)))
		return -1;
	if(lstat(path, &statp) || !S_ISREG(statp.st_mode))
		goto end; // Will return 0;
	snprintf(msg, sizeof(msg), "%s\n", file);
	ret=send_data_to_client(srfd, msg, strlen(msg));
end:
	free_w(&path);
	return ret;
}

static int browse_manifest(struct asfd *srfd, gzFile zp, const char *browse)
{
	int ret=0;
/*
	int ars=0;
	char ls[1024]="";
	struct sbuf sb;
	struct cntr cntr;
	size_t blen=0;
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

		if(send_data_to_client(srfd, ls, strlen(ls))
		  || send_data_to_client(srfd, "\n", 1))
		{
			ret=-1;
			break;
		}
	}
	free_sbuf(&sb);
*/
	return ret;
}

static int list_backup_file_contents(struct asfd *srfd,
	const char *dir, const char *file, const char *browse)
{
	int ret=-1;
	size_t l=0;
	gzFile zp=NULL;
	char *path=NULL;
	char buf[256]="";
	if(!(path=prepend_s(dir, file))
	  || !(zp=gzopen_file(path, "rb")))
		goto end;

	if(send_data_to_client(srfd, "-list begin-\n", strlen("-list begin-\n")))
		goto end;

	if(!strcmp(file, "manifest.gz"))
	{
		if(browse_manifest(srfd, zp, browse?:"")) goto end;
	}
	else
	{
		while((l=gzread(zp, buf, sizeof(buf)))>0)
			if(send_data_to_client(srfd, buf, l)) goto end;
	}
	if(send_data_to_client(srfd, "-list end-\n", strlen("-list end-\n")))
		goto end;
	ret=0;
end:
	gzclose_fp(&zp);
	free_w(&path);
	return ret;
}

static int list_backup_dir(struct asfd *srfd, struct cstat *cli, unsigned long bno)
{
	int ret=0;
	struct bu *bu;
        struct bu *bu_list=NULL;
	if(bu_list_get_str(cli->basedir, &bu_list, 0))
		goto error;

	if(!bu_list) goto end;
	for(bu=bu_list; bu; bu=bu->next) if(bu->bno==bno) break;
	if(!bu) goto end;

	if(send_data_to_client(srfd, "-list begin-\n", strlen("-list begin-\n")))
		goto error;
	list_backup_file_name(srfd, bu->path, "manifest.gz");
	list_backup_file_name(srfd, bu->path, "log.gz");
	list_backup_file_name(srfd, bu->path, "restorelog.gz");
	list_backup_file_name(srfd, bu->path, "verifylog.gz");
	if(send_data_to_client(srfd, "-list end-\n", strlen("-list end-\n")))
		goto error;
	goto end;
error:
	ret=-1;
end:
	bu_list_free(&bu_list);
	return ret;
}

static int list_backup_file(struct asfd *srfd, struct cstat *cli, unsigned long bno, const char *file, const char *browse)
{
	int ret=0;
        struct bu *bu=NULL;
        struct bu *bu_list=NULL;
	if(bu_list_get_str(cli->basedir, &bu_list, 0))
		goto error;

	if(!bu_list) goto end;
	for(bu=bu_list; bu; bu=bu->next) if(bu->bno==bno) break;
	if(!bu) goto end;
	printf("found: %s\n", bu->path);
	list_backup_file_contents(srfd, bu->path, file, browse);
	goto end;
error:
	ret=-1;
end:
	bu_list_free(&bu_list);
	return ret;
}

static char *get_str(const char **buf, const char *pre, int last)
{
	size_t len=0;
	char *cp=NULL;
	char *copy=NULL;
	char *ret=NULL;
	if(!buf || !*buf) goto end;
	len=strlen(pre);
	if(strncmp(*buf, pre, len)
	  || !(copy=strdup((*buf)+len)))
		goto end;
	if(!last && (cp=strchr(copy, ':'))) *cp='\0';
	*buf+=len+strlen(copy)+1;
	ret=strdup(copy);
end:
	free_w(&copy);
	return ret;
}

static int parse_client_data(struct asfd *srfd, struct cstat **clist, int clen)
{
	int ret=0;
	const char *cp=NULL;
	char *client=NULL;
	char *backup=NULL;
	char *file=NULL;
	char *browse=NULL;
	unsigned long bno=0;
	struct cstat *cli=NULL;
printf("got client data: '%s'\n", srfd->rbuf->buf);

	cp=srfd->rbuf->buf;
	client=get_str(&cp, "c:", 0);
	backup=get_str(&cp, "b:", 0);
	file  =get_str(&cp, "f:", 0);
	browse=get_str(&cp, "p:", 1);
	if(browse)
	{
		free_w(&file);
		if(!(file=strdup_w("manifest.gz", __func__)))
			goto error;
		strip_trailing_slashes(&browse);
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
				list_backup_file(srfd, cli, bno, file, browse);
			}
			else
			{
				printf("list backup %lu of client '%s'\n",
					bno, client);
				printf("basedir: %s\n", cli->basedir);
				list_backup_dir(srfd, cli, bno);
			}
		}
		else
		{
			//printf("detail request: %s\n", rbuf);
			if(send_summaries_to_client(srfd, clist, clen, client))
				goto error;
		}
	}
	else
	{
		//printf("summaries request\n");
		if(send_summaries_to_client(srfd, clist, clen, NULL))
			goto error;
	}

	goto end;
error:
	ret=-1;
end:
	free_w(&client);
	free_w(&backup);
	free_w(&file);
	free_w(&browse);
	return ret;
}

static int parse_data(struct asfd *asfd, struct cstat **clist, int clen)
{
	// Hacky to switch on whether it is using line buffering or not.
	if(asfd->linebuf) return parse_client_data(asfd, clist, clen);
	return parse_parent_data(asfd, clist, clen);
}

static int main_loop(struct async *as, struct conf *conf)
{
	int clen=0;
	struct cstat **clist=NULL;
	int gotdata=0;
	struct asfd *asfd;
	while(1)
	{
		// Take the opportunity to get data from the disk if nothing
		// was read from the fds.
		if(gotdata) gotdata=0;
		else if(load_data_from_disk(&clist, &clen, conf))
			goto error;
		if(as->read_write(as))
		{
			logp("Exiting main status server loop\n");
			break;
		}
		for(asfd=as->asfd; asfd; asfd=asfd->next)
			while(asfd->rbuf->buf)
		{
			gotdata=1;
			if(parse_data(asfd, clist, clen)
			  || asfd->parse_readbuf(asfd))
				goto error;
			iobuf_free_content(asfd->rbuf);
		}
	}
	return 0;
error:
	return -1;
}

static int setup_asfd(struct async *as, const char *desc, int *fd,
	int linebuf, struct conf *conf)
{
	struct asfd *asfd=NULL;
	if(!fd || *fd<0) return 0;
	set_non_blocking(*fd);
	if(!(asfd=asfd_alloc())
	  || asfd->init(asfd, desc, as, *fd, NULL, linebuf, conf))
		goto error;
	*fd=-1;
	as->asfd_add(as, asfd);
	return 0;
error:
	asfd_free(&asfd);
	return -1;
}

// Incoming status request.
int status_server(int *cfd, int *status_rfd, struct conf *conf)
{
	int ret=-1;
	struct async *as=NULL;

	// Need to get status information from status_rfd.
	// Need to read from cfd to find out what the client wants, and
	// therefore what status to write back to cfd.

	if(!(as=async_alloc())
	  || as->init(as, 0)
	  || setup_asfd(as, "status client socket",
		cfd, 1 /* linebuf */, conf)
	  || setup_asfd(as, "status server parent socket",
		status_rfd, 0 /* standard */, conf))
			goto end;

	ret=main_loop(as, conf);
end:
	async_asfd_free_all(&as);
	close_fd(cfd);
	close_fd(status_rfd);
	return ret;
}
