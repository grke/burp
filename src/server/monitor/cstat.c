#include "include.h"
#include "../../bu.h"
#include "../../lock.h"
#include "../bu_get.h"
#include "../sdirs.h"

#include <dirent.h>

static int permitted(struct cstat *cstat,
	struct conf **parentconfs, struct conf **cconfs)
{
	struct strlist *rclient;

	// Allow clients to look at themselves.
	if(!strcmp(cstat->name, get_string(parentconfs[OPT_CNAME]))) return 1;

	// Do not allow clients using the restore_client option to see more
	// than the client that it is pretending to be.
	if(get_string(parentconfs[OPT_RESTORE_CLIENT])) return 0;

	// If we are listed in this restore_client list.
	for(rclient=get_strlist(cconfs[OPT_RESTORE_CLIENTS]);
	  rclient; rclient=rclient->next)
		if(!strcmp(get_string(parentconfs[OPT_CNAME]), rclient->path))
			return 1;
	return 0;
}

static int set_cstat_from_conf(struct cstat *cstat,
	struct conf **parentconfs, struct conf **cconfs)
{
	// Make sure the permitted flag is set appropriately.
	cstat->permitted=permitted(cstat, parentconfs, cconfs);

	cstat->protocol=get_e_protocol(cconfs[OPT_PROTOCOL]);
	sdirs_free((struct sdirs **)&cstat->sdirs);
	if(!(cstat->sdirs=sdirs_alloc())
	  || sdirs_init((struct sdirs *)cstat->sdirs, cconfs)) return -1;
	return 0;
}

static int get_client_names(struct cstat **clist, struct conf **confs)
{
	int m=0;
	int n=-1;
	int ret=-1;
	struct cstat *c;
	struct cstat *cnew;
	struct dirent **dir=NULL;
	const char *clientconfdir=get_string(confs[OPT_CLIENTCONFDIR]);

	if((n=scandir(clientconfdir, &dir, 0, 0))<0)
	{
		logp("could not scandir clientconfdir: %s\n",
			clientconfdir, strerror(errno));
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
		  || cstat_init(cnew, dir[m]->d_name, clientconfdir)
		  || cstat_add_to_list(clist, cnew))
			goto end;
	}

	ret=0;
end:
	for(m=0; m<n; m++) free_v((void **)&dir[m]);
	free_v((void **)&dir);
	return ret;
}

static void cstat_free_w(struct cstat **cstat)
{
	sdirs_free((struct sdirs **)(*cstat)->sdirs);
	cstat_free(cstat);
}

static void cstat_remove(struct cstat **clist, struct cstat **cstat)
{
	struct cstat *c;
	struct cstat *clast=NULL;
	if(!cstat || !*cstat) return;
	if(*clist==*cstat)
	{
		*clist=(*cstat)->next;
		cstat_free_w(cstat);
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
		cstat_free_w(cstat);
		*cstat=*clist;

		return;
	}
}

static int reload_from_client_confs(struct cstat **clist,
	struct conf **globalcs)
{
	struct cstat *c;
	struct stat statp;
	static struct conf **cconfs=NULL;
	static time_t global_mtime=0;
	time_t global_mtime_new=0;
	const char *globalconffile=get_string(globalcs[OPT_CONFFILE]);

	if(!cconfs && !(cconfs=confs_alloc())) goto error;

	if(stat(globalconffile, &statp)
	  || !S_ISREG(statp.st_mode))
	{
		logp("Could not stat main conf file %s: %s\n",
			globalconffile, strerror(errno));
		goto error;
	}
	global_mtime_new=statp.st_mtime;

	// FIX THIS: If '. included' conf files have changed, this code will
	// not detect them. I guess that conf.c should make a list of them.
	while(1)
	{
		for(c=*clist; c; c=c->next)
		{
			// Look at the client conf files to see if they have
			// changed, and reload bits and pieces if they have.

			if(!c->conffile) continue;
			if(stat(c->conffile, &statp)
			  || !S_ISREG(statp.st_mode))
			{
				cstat_remove(clist, &c);
				break; // Go to the beginning of the list.
			}
			if(statp.st_mtime==c->conf_mtime
			  && global_mtime_new==global_mtime)
			{
				// The conf files have not changed - no need to
				// do anything.
				continue;
			}
			c->conf_mtime=statp.st_mtime;

			confs_free_content(cconfs);
			if(set_string(cconfs[OPT_CNAME], c->name))
				goto error;
			if(conf_load_clientconfdir(globalcs, cconfs))
			{
				cstat_remove(clist, &c);
				break; // Go to the beginning of the list.
			}

			if(set_cstat_from_conf(c, globalcs, cconfs))
				goto error;
		}
		// Only stop if the end of the list was not reached.
		if(!c) break;
	}
	if(global_mtime!=global_mtime_new)
		global_mtime=global_mtime_new;
	return 0;
error:
	confs_free(&cconfs);
	return -1;
}

int cstat_set_run_status(struct cstat *cstat)
{
	struct stat statp;
	struct sdirs *sdirs=(struct sdirs *)cstat->sdirs;
	if(!cstat->permitted) return 0;

	if(lstat(sdirs->lock->path, &statp))
	{
		if(lstat(sdirs->working, &statp))
			cstat->run_status=RUN_STATUS_IDLE;
		else
			cstat->run_status=RUN_STATUS_CLIENT_CRASHED;
	}
	else
	{
		if(!lock_test(sdirs->lock->path)) // Could have got lock.
			cstat->run_status=RUN_STATUS_SERVER_CRASHED;
		else
			cstat->run_status=RUN_STATUS_RUNNING;
	}

	return 0;
}

static int reload_from_clientdir(struct cstat **clist, struct conf **confs)
{
	struct cstat *c;
	for(c=*clist; c; c=c->next)
	{
		time_t ltime=0;
		struct stat statp;
		struct stat lstatp;
		struct sdirs *sdirs;

		if(!c->permitted) continue;

		sdirs=(struct sdirs *)c->sdirs;
		if(!sdirs->client) continue;
		if(stat(sdirs->client, &statp))
		{
			// No clientdir.
			if(!c->run_status
			  && cstat_set_run_status(c))
				goto error;
			continue;
		}
		if(!lstat(sdirs->lock->path, &lstatp))
			ltime=lstatp.st_mtime;
		if(statp.st_mtime==c->clientdir_mtime
		  && ltime==c->lockfile_mtime
		  && c->run_status!=RUN_STATUS_SERVER_CRASHED)
		  //&& !c->cntr)
		{
			// clientdir has not changed - no need to do anything.
			continue;
		}
		c->clientdir_mtime=statp.st_mtime;
		c->lockfile_mtime=ltime;
		if(cstat_set_run_status(c)) goto error;

		bu_list_free(&c->bu);
// FIX THIS: should probably not load everything each time.
//		if(bu_get_current(sdirs, &c->bu))
//			goto error;
		if(bu_get_list_with_working(sdirs, &c->bu, c))
			goto error;
	}
	return 0;
error:
	return -1;
}

int cstat_load_data_from_disk(struct cstat **clist, struct conf **globalcs)
{
	return get_client_names(clist, globalcs)
	  || reload_from_client_confs(clist, globalcs)
	  || reload_from_clientdir(clist, globalcs);
}

int cstat_set_backup_list(struct cstat *cstat)
{
	struct bu *bu=NULL;

	if(!cstat->permitted) return 0;

	// Free any previous list.
	bu_list_free(&cstat->bu);

	if(bu_get_list_with_working((struct sdirs *)cstat->sdirs, &bu, cstat))
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
