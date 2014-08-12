#include "include.h"

#include <dirent.h>

struct cstat *cstat_alloc(void)
{
	return (struct cstat *)calloc_w(1, sizeof(struct cstat), __func__);
}

int cstat_init(struct cstat *cstat,
	const char *name, const char *clientconfdir)
{
	if((clientconfdir && !(cstat->conffile=prepend_s(clientconfdir, name)))
	  || !(cstat->name=strdup_w(name, __func__))
	  || !(cstat->sdirs=sdirs_alloc()))
		return -1;
	return 0;
}

static void cstat_free_content(struct cstat *c)
{
	if(!c) return;
	bu_list_free(&c->bu);
	free_w(&c->name);
	free_w(&c->conffile);
	free_w(&c->running_detail);
	sdirs_free_content(c->sdirs);
	c->clientdir_mtime=0;
	c->lockfile_mtime=0;
}

void cstat_free(struct cstat **cstat)
{
	if(!cstat || !*cstat) return;
	cstat_free_content(*cstat);
	free_v((void **)cstat);
}

int cstat_add_to_list(struct cstat **clist, struct cstat *cnew)
{
	struct cstat *c=NULL;
	struct cstat *clast=NULL;

	for(c=*clist; c; c=c->next)
	{
		if(strcmp(cnew->name, c->name)<0) break;
		c->prev=clast;
		clast=c;
	}
	if(clast)
	{
		cnew->next=clast->next;
		clast->next=cnew;
		cnew->prev=clast;
	}
	else
	{
		*clist=cnew;
		cnew->next=c;
	}

	return 0;
}

static int set_cstat_from_conf(struct cstat *c, struct conf *cconf)
{
	sdirs_free_content(c->sdirs);
	if(sdirs_init(c->sdirs, cconf)) return -1;
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
	struct cstat *clast=NULL;
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
		if(c->next!=*cstat)
		{
			clast=c;
			continue;
		}
		c->next=(*cstat)->next;
		c->prev=clast;
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

	while(1)
	{
		for(c=*clist; c; c=c->next)
		{
			// Look at the client conf files to see if they have
			// changed, and reload bits and pieces if they have.
			struct stat statp;

			if(!c->conffile) continue;
			if(stat(c->conffile, &statp)
			  || !S_ISREG(statp.st_mode))
			{
				cstat_remove(clist, &c);
				break; // Go to the beginning of the list.
			}
			if(statp.st_mtime==c->conf_mtime)
			{
				// conf file has not changed - no need to do
				// anything.
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
				break; // Go to the beginning of the list.
			}

			if(set_cstat_from_conf(c, cconf))
				goto error;
		}
		// Only stop if the end of the list was not reached.
		if(!c) break;
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
		case STATUS_IDLE: return STATUS_STR_IDLE;
		case STATUS_CLIENT_CRASHED: return STATUS_STR_CLIENT_CRASHED;
		case STATUS_SERVER_CRASHED: return STATUS_STR_SERVER_CRASHED;
		case STATUS_RUNNING: return STATUS_STR_RUNNING;
		case STATUS_SCANNING: return STATUS_STR_SCANNING;
		case STATUS_BACKUP: return STATUS_STR_BACKUP;
		case STATUS_MERGING: return STATUS_STR_MERGING;
		case STATUS_SHUFFLING: return STATUS_STR_SHUFFLING;
		case STATUS_LISTING: return STATUS_STR_LISTING;
		case STATUS_RESTORING: return STATUS_STR_RESTORING;
		case STATUS_VERIFYING: return STATUS_STR_VERIFYING;
		case STATUS_DELETING: return STATUS_STR_DELETING;
		default: return "unknown";
	}
}

enum cstat_status cstat_str_to_status(const char *str)
{
	if(!strcmp(str, STATUS_STR_IDLE)) return STATUS_IDLE;
	else if(!strcmp(str, STATUS_STR_RUNNING)) return STATUS_RUNNING;
	else if(!strcmp(str, STATUS_STR_CLIENT_CRASHED))
		return STATUS_CLIENT_CRASHED;
	else if(!strcmp(str, STATUS_STR_SERVER_CRASHED))
		return STATUS_CLIENT_CRASHED;
	else if(!strcmp(str, STATUS_STR_RUNNING)) return STATUS_RUNNING;
	else if(!strcmp(str, STATUS_STR_SCANNING)) return STATUS_SCANNING;
	else if(!strcmp(str, STATUS_STR_BACKUP)) return STATUS_BACKUP;
	else if(!strcmp(str, STATUS_STR_MERGING)) return STATUS_MERGING;
	else if(!strcmp(str, STATUS_STR_SHUFFLING)) return STATUS_SHUFFLING;
	else if(!strcmp(str, STATUS_STR_LISTING)) return STATUS_LISTING;
	else if(!strcmp(str, STATUS_STR_RESTORING)) return STATUS_RESTORING;
	else if(!strcmp(str, STATUS_STR_VERIFYING)) return STATUS_VERIFYING;
	else if(!strcmp(str, STATUS_STR_DELETING)) return STATUS_DELETING;
	return STATUS_UNSET;
}

int cstat_set_status(struct cstat *cstat)
{
	struct stat statp;

	if(lstat(cstat->sdirs->lock->path, &statp))
	{
		if(lstat(cstat->sdirs->working, &statp))
			cstat->status=STATUS_IDLE;
		else
			cstat->status=STATUS_CLIENT_CRASHED;
		// It is not running, so free the running_detail.
		free_w(&cstat->running_detail);
	}
	else
	{
		if(!lock_test(cstat->sdirs->lock->path)) // Could have got lock.
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

static int reload_from_clientdir(struct cstat **clist, struct conf *conf)
{
	struct cstat *c;
	for(c=*clist; c; c=c->next)
	{
		time_t ltime=0;
		struct stat statp;
		struct stat lstatp;
		if(!c->sdirs->client) continue;
		if(stat(c->sdirs->client, &statp))
		{
			// No clientdir.
			if(!c->status
			  && cstat_set_status(c))
				goto error;
			continue;
		}
		if(!lstat(c->sdirs->lock->path, &lstatp))
			ltime=lstatp.st_mtime;
		if(statp.st_mtime==c->clientdir_mtime
		  && ltime==c->lockfile_mtime
		  && c->status!=STATUS_SERVER_CRASHED
		  && !c->running_detail)
		{
			// clientdir has not changed - no need to do anything.
			continue;
		}
		c->clientdir_mtime=statp.st_mtime;
		c->lockfile_mtime=ltime;
		if(cstat_set_status(c)) goto error;

		bu_list_free(&c->bu);
		if(bu_current_get(c->sdirs, &c->bu))
			goto error;
	}
	return 0;
error:
	return -1;
}

int cstat_load_data_from_disk(struct cstat **clist, struct conf *conf)
{
	return get_client_names(clist, conf)
	  || reload_from_client_confs(clist, conf)
	  || reload_from_clientdir(clist, conf);
}

int cstat_set_backup_list(struct cstat *cstat)
{
	struct bu *bu=NULL;

	// Free any previous list.
	bu_list_free(&cstat->bu);

	if(bu_list_get_with_working(cstat->sdirs, &bu))
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
