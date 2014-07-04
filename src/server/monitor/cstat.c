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

static void cstat_free_content(struct cstat *c)
{
	if(!c) return;
	free_w(&c->name);
	free_w(&c->conffile);
	free_w(&c->running_detail);
	free_w(&c->basedir);
	free_w(&c->working);
	free_w(&c->current);
	free_w(&c->timestamp);
	free_w(&c->lockfile);
}

static void cstat_free(struct cstat **c)
{
	if(!c || !*c) return;
	cstat_free_content(*c);
	free_v((void **)c);
}

static int cstat_add_to_list(struct cstat **clist, struct cstat *cnew)
{
	struct cstat *c=NULL;
	struct cstat *clast=NULL;

	for(c=*clist; c; c=c->next)
	{
		if(strcmp(cnew->name, c->name)<0) break;
		clast=c;
	}
	if(clast)
	{
		cnew->next=clast->next;
		clast->next=cnew;
	}
	else
	{
		*clist=cnew;
		cnew->next=c;
	}

	return 0;
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

static int get_client_names(struct cstat **clist, struct conf *conf)
{
	int m=0;
	int n=-1;
	int ret=-1;
	struct cstat *c;
	struct cstat *cnew;
	struct dirent **dir=NULL;

	if((n=scandir(conf->clientconfdir, &dir, 0, 0))<0)
	{
		logp("could not scandir clientconfdir: %s\n",
			conf->clientconfdir, strerror(errno));
		goto end;
	}
        for(m=0; m<n; m++)
	{
		if(dir[m]->d_ino==0
		// looks_like...() also avoids '.' and '..'.
		  || looks_like_tmp_or_hidden_file(dir[m]->d_name))
			continue;
		for(c=*clist; c; c=c->next)
		{
			if(!c->name) continue;
			if(!strcmp(dir[m]->d_name, c->name))
				break;
		}
		if(c) continue;

		// We do not have this client yet. Add it.
		if(!(cnew=cstat_alloc())
		  || cstat_init(cnew, dir[m]->d_name, conf->clientconfdir)
		  || cstat_add_to_list(clist, cnew))
			goto end;
	}

	ret=0;
end:
	for(m=0; m<n; m++) free_v((void **)&dir[m]);
	free_v((void **)&dir);
	return ret;
}

static void cstat_remove(struct cstat **clist, struct cstat **cstat)
{
	struct cstat *c;
	if(!cstat || !*cstat) return;
	if(*clist==*cstat)
	{
		*clist=(*cstat)->next;
		cstat_free(cstat);
		*cstat=*clist;
		return;
	}
	for(c=*clist; c; c=c->next)
	{
		if(c->next!=*cstat) continue;
		c->next=(*cstat)->next;
		cstat_free(cstat);
		*cstat=*clist;
		return;
	}
}

static int reload_from_client_confs(struct cstat **clist, struct conf *conf)
{
	struct cstat *c;
	static struct conf *cconf=NULL;

	if(!cconf && !(cconf=conf_alloc())) goto error;

	for(c=*clist; c; c=c->next)
	{
		// Look at the client conf files to see if they have changed,
		// and reload bits and pieces if they have.
		struct stat statp;

		if(!c->conffile) continue;

		if(stat(c->conffile, &statp)
		  || !S_ISREG(statp.st_mode))
		{
			cstat_remove(clist, &c);
			continue;
		}
		if(statp.st_mtime==c->conf_mtime)
		{
			// conf file has not changed - no need to do anything.
			continue;
		}
		c->conf_mtime=statp.st_mtime;

		conf_free_content(cconf);
		if(!(cconf->cname=strdup_w(c->name, __func__)))
			goto error;
		if(conf_set_client_global(conf, cconf)
		  || conf_load(c->conffile, cconf, 0))
		{
			cstat_remove(clist, &c);
			continue;
		}

		if(set_cstat_from_conf(c, conf, cconf))
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

static int reload_from_basedir(struct cstat **clist, struct conf *conf)
{
	struct cstat *c;
	for(c=*clist; c; c=c->next)
	{
		// Pretty much the same routine for the basedir, except also
		// reload if we have running_detail.
		time_t ltime=0;
		struct stat statp;
		struct stat lstatp;
		if(!c->basedir) continue;
		if(stat(c->basedir, &statp))
		{
			// no basedir
			if(!c->status
			  && cstat_set_status(c))
				goto error;
			continue;
		}
		if(!lstat(c->lockfile, &lstatp))
			ltime=lstatp.st_mtime;
		if(statp.st_mtime==c->basedir_mtime
		  && ltime==c->lockfile_mtime
		  && c->status!=STATUS_SERVER_CRASHED
		  && !c->running_detail)
		{
			// basedir has not changed - no need to do anything.
			continue;
		}
		c->basedir_mtime=statp.st_mtime;
		c->lockfile_mtime=ltime;

		if(cstat_set_status(c)) goto error;
	}
	return 0;
error:
	return -1;
}

int cstat_load_data_from_disk(struct cstat **clist, struct conf *conf)
{
	return get_client_names(clist, conf)
	  || reload_from_client_confs(clist, conf)
	  || reload_from_basedir(clist, conf);
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

struct cstat *cstat_get_by_name(struct cstat *clist, const char *name)
{
	struct cstat *c;
        for(c=clist; c; c=c->next) if(!strcmp(c->name, name)) return c;
        return NULL;
}
