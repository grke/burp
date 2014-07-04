#include "include.h"

#include <dirent.h>

static struct cstat *cstat_alloc(void)
{
	return (struct cstat *)calloc_w(1, sizeof(struct cstat), __func__);
}

static int cstat_init(struct cstat *cstat,
	const char *name, const char *clientconfdir)
{
	if(!(cstat->conffile=prepend_s(clientconfdir, name))
	  || !(cstat->name=strdup_w(name, __func__)))
		return -1;
	return 0;
}

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
		if(!(*clist)[q]->name)
			return cstat_init((*clist)[q], name, clientconfdir);

	// Otherwise, increase the size of the array.

	if(!(ctmp=(struct cstat **)realloc_w(*clist,
		((*clen)+1)*sizeof(struct cstat *), __func__)))
			return -1;
	*clist=ctmp;
	if(!(cnew=cstat_alloc())
	  || cstat_init(cnew, name, clientconfdir))
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

const char *cstat_status_to_str(struct cstat *cstat)
{
	switch(cstat->status)
	{
		case STATUS_IDLE:
			return "idle";
		case STATUS_CLIENT_CRASHED:
			return "client crashed";
		case STATUS_SERVER_CRASHED:
			return "server crashed";
		case STATUS_RUNNING:
			return "running";
		default:
			return "unknown";
	}
}

int cstat_set_status(struct cstat *cstat)
{
	struct stat statp;
//logp("in set summary for %s\n", cstat->name);

	if(lstat(cstat->lockfile, &statp))
	{
		if(lstat(cstat->working, &statp))
			cstat->status=STATUS_IDLE;
		else
			cstat->status=STATUS_CLIENT_CRASHED;
		// It is not running, so free the running_detail.
		free_w(&cstat->running_detail);
	}
	else
	{
		if(!lock_test(cstat->lockfile)) // could have got lock
		{
			cstat->status=STATUS_SERVER_CRASHED;
			// It is not running, so free the running_detail.
			free_w(&cstat->running_detail);
		}
		else
			cstat->status=STATUS_RUNNING;
	}

	return 0;
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
			if(!(*clist)[q]->status
			  && cstat_set_status((*clist)[q]))
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

		if(cstat_set_status((*clist)[q])) goto error;
	}
	return 0;
error:
	return -1;
}

int cstat_load_data_from_disk(struct cstat ***clist,
	int *clen, struct conf *conf)
{
	return get_client_names(conf, clist, clen)
	  || reload_from_client_confs(conf, clist, clen)
	  || reload_from_basedir(conf, clist, clen);
}

int cstat_set_backup_list(struct cstat *cstat)
{
	struct bu *bu=NULL;

	// Free any previous list.
	bu_list_free(&cstat->bu);

	// FIX THIS: If this stuff used sdirs, there would be no need for a
	// separate bu_list_get_str function.
	if(bu_list_get_str(cstat->basedir, &bu, 0))
	{
		//logp("error when looking up current backups\n");
		return 0;
	}

	// Find the end of the list just loaded, so we can traverse
	// it backwards later.
	while(bu && bu->next) bu=bu->next;

	cstat->bu=bu;
	return 0;
}
