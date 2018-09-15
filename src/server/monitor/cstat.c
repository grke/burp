#include "../../burp.h"
#include "../../alloc.h"
#include "../../bu.h"
#include "../../cstat.h"
#include "../../conffile.h"
#include "../../fsops.h"
#include "../../lock.h"
#include "../../log.h"
#include "../../strlist.h"
#include "../bu_get.h"
#include "../sdirs.h"
#include "cstat.h"

#ifndef UTEST
static 
#endif
int cstat_permitted(struct cstat *cstat,
	struct conf **monitor_cconfs, struct conf **cconfs)
{
	struct strlist *rclient;
	const char *monitorconf_cname;

	monitorconf_cname=get_string(monitor_cconfs[OPT_CNAME]);
	if(!monitorconf_cname)
		return 0;

	// Allow clients to look at themselves.
	if(!strcmp(cstat->name, monitorconf_cname))
		return 1;

	// Do not allow clients using the super_client option to see more
	// than the client that it is pretending to be.
	if(get_string(monitor_cconfs[OPT_SUPER_CLIENT]))
		return 0;

	// If we are listed in this restore_client list, or super_client list.
	for(rclient=get_strlist(cconfs[OPT_RESTORE_CLIENTS]);
	  rclient; rclient=rclient->next)
	    if(!strcmp(get_string(monitor_cconfs[OPT_CNAME]), rclient->path))
		return 1;
	for(rclient=get_strlist(cconfs[OPT_SUPER_CLIENTS]);
	  rclient; rclient=rclient->next)
	    if(!strcmp(get_string(monitor_cconfs[OPT_CNAME]), rclient->path))
		return 1;
	return 0;
}

static int cstat_set_sdirs_protocol_unknown(struct cstat *cstat,
	struct conf **cconfs)
{
	struct stat buf1;
	struct stat buf2;
	struct sdirs *sdirs1=NULL;
	struct sdirs *sdirs2=NULL;

	if(!(sdirs1=sdirs_alloc())
	  || !(sdirs2=sdirs_alloc()))
		goto error;

	set_protocol(cconfs, PROTO_1);
	if(sdirs_init_from_confs(sdirs1, cconfs))
		goto error;
	set_protocol(cconfs, PROTO_2);
	if(sdirs_init_from_confs(sdirs2, cconfs))
		goto error;

	if(lstat(sdirs2->client, &buf2))
		goto protocol1; // No protocol2 client directory.

	if(lstat(sdirs1->client, &buf1))
		goto protocol2; // No protocol1 client directory.

	// Both directories exist.

	if(buf2.st_mtime>buf1.st_mtime)
		goto protocol2; // 2 was modified most recently.

	// Fall through to protocol1.

protocol1:
	cstat->sdirs=sdirs1;
	cstat->protocol=PROTO_1;
	sdirs_free(&sdirs2);
	set_protocol(cconfs, PROTO_AUTO);
	return 0;
protocol2:
	cstat->sdirs=sdirs2;
	cstat->protocol=PROTO_2;
	sdirs_free(&sdirs1);
	set_protocol(cconfs, PROTO_AUTO);
	return 0;
error:
	sdirs_free(&sdirs1);
	sdirs_free(&sdirs2);
	set_protocol(cconfs, PROTO_AUTO);
	return -1;
}

static int cstat_set_sdirs_protocol_known(struct cstat *cstat,
	struct conf **cconfs)
{
	struct sdirs *sdirs=NULL;

	if(!(sdirs=sdirs_alloc()))
		return -1;
	if(sdirs_init_from_confs(sdirs, cconfs))
	{
		sdirs_free(&sdirs);
		return -1;
	}
	cstat->sdirs=sdirs;
	return 0;
}

static int cstat_set_sdirs(struct cstat *cstat, struct conf **cconfs)
{
	enum protocol protocol=get_protocol(cconfs);
	sdirs_free((struct sdirs **)&cstat->sdirs);

	if(protocol==PROTO_AUTO)
		return cstat_set_sdirs_protocol_unknown(cstat, cconfs);

	cstat->protocol=protocol;
	return cstat_set_sdirs_protocol_known(cstat, cconfs);
}

static int set_cstat_from_conf(struct cstat *cstat,
	struct conf **monitor_cconfs, struct conf **cconfs)
{
	struct strlist *s=NULL;
	// Make sure the permitted flag is set appropriately.
	cstat->permitted=cstat_permitted(cstat, monitor_cconfs, cconfs);

	if(cstat_set_sdirs(cstat, cconfs))
		return -1;
	strlists_free(&cstat->labels);
	for(s=get_strlist(cconfs[OPT_LABEL]); s; s=s->next)
		if(strlist_add_sorted(&cstat->labels, s->path, s->flag))
			return -1;
	return 0;
}

#ifndef UTEST
static
#endif
int cstat_get_client_names(struct cstat **clist, const char *clientconfdir)
{
	int i=0;
	int n=0;
	int ret=-1;
	struct cstat *c;
	struct cstat *cnew;
	struct dirent **dir=NULL;

	if((n=scandir(clientconfdir, &dir, filter_dot, NULL))<0)
	{
		logp("scandir failed for %s in %s: %s\n",
			clientconfdir, __func__, strerror(errno));
		goto end;
	}
	for(i=0; i<n; i++)
	{
		if(!cname_valid(dir[i]->d_name))
			continue;
		for(c=*clist; c; c=c->next)
		{
			if(!c->name) continue;
			if(!strcmp(dir[i]->d_name, c->name))
				break;
		}
		if(c) continue;

		// We do not have this client yet. Add it.
		if(!(cnew=cstat_alloc())
		  || cstat_init(cnew, dir[i]->d_name, clientconfdir))
			goto end;
		cstat_add_to_list(clist, cnew);
	}

	ret=0;
end:
	if(dir)
	{
		for(i=0; i<n; i++)
			free(dir[i]);
		free(dir);
	}
	return ret;
}

static void cstat_free_w(struct cstat **cstat)
{
	sdirs_free((struct sdirs **)&(*cstat)->sdirs);
	cstat_free(cstat);
}

#ifndef UTEST
static
#endif
void cstat_remove(struct cstat **clist, struct cstat **cstat)
{
	struct cstat *c;
	if(!cstat || !*cstat) return;
	if(*clist==*cstat)
	{
		*clist=(*clist)->next;
		if(*clist) (*clist)->prev=NULL;
		cstat_free_w(cstat);
		*cstat=*clist;
		return;
	}
	for(c=*clist; c; c=c->next)
	{
		if(c->next!=*cstat)
			continue;
		c->next=(*cstat)->next;
		if(c->next)
			c->next->prev=(*cstat)->prev;
		cstat_free_w(cstat);
		*cstat=*clist;
		return;
	}
}

// Returns -1 on error, otherwise the number of clients that were reloaded.
#ifndef UTEST
static
#endif
int cstat_reload_from_client_confs(struct cstat **clist,
	struct conf **monitor_cconfs,
	struct conf **globalcs, struct conf **cconfs)
{
	struct cstat *c;
	struct stat statp;
	static time_t global_mtime=0;
	time_t global_mtime_new=0;
	const char *globalconffile;
	int reloaded=0;

	globalconffile=get_string(globalcs[OPT_CONFFILE]);

	if(stat(globalconffile, &statp)
	  || !S_ISREG(statp.st_mode))
	{
		logp("Could not stat main conf file %s: %s\n",
			globalconffile, strerror(errno));
		return -1;
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
				return -1;
			if(conf_load_clientconfdir(globalcs, cconfs))
			{
				// If the file has junk in it, we will keep
				// trying to reload it after removal.
				// So, just deny permission to view it.
				c->permitted=0;
				continue;
			}

			if(set_cstat_from_conf(c, monitor_cconfs, cconfs))
				return -1;
			reloaded++;
		}
		// Only stop if the end of the list was not reached.
		if(!c) break;
	}
	if(global_mtime!=global_mtime_new)
		global_mtime=global_mtime_new;
	return reloaded;
}

void cstat_set_run_status(struct cstat *cstat, enum run_status run_status)
{
	if(!cstat->permitted)
		return;
	cstat->run_status=run_status;
}

// Return -1 on error, or the number of reloaded clients.
#ifndef UTEST
static
#endif
int reload_from_clientdir(struct cstat **clist)
{
	int reloaded=0;
	struct cstat *c;
	for(c=*clist; c; c=c->next)
	{
		struct stat statp;
		struct sdirs *sdirs;

		if(!c->permitted) continue;

		sdirs=(struct sdirs *)c->sdirs;
		if(!sdirs || !sdirs->client) continue;
		if(stat(sdirs->client, &statp))
			continue;

		if(statp.st_mtime==c->clientdir_mtime)
		{
			// clientdir has not changed - no need to do anything.
			continue;
		}
		c->clientdir_mtime=statp.st_mtime;

		bu_list_free(&c->bu);
// FIX THIS: should probably not load everything each time.
//		if(bu_get_current(sdirs, &c->bu))
//			goto error;
		if(bu_get_list_with_working(sdirs, &c->bu))
			goto error;
		reloaded++;
	}
	return reloaded;
error:
	return -1;
}

int cstat_load_data_from_disk(struct cstat **clist,
	struct conf **monitor_cconfs,
	struct conf **globalcs, struct conf **cconfs)
{
	if(!globalcs) return -1;
	return cstat_get_client_names(clist,
		get_string(globalcs[OPT_CLIENTCONFDIR]))
	  || cstat_reload_from_client_confs(clist,
		monitor_cconfs, globalcs, cconfs)<0
	  || reload_from_clientdir(clist)<0;
}

int cstat_set_backup_list(struct cstat *cstat)
{
	struct bu *bu=NULL;

	// Free any previous list.
	bu_list_free(&cstat->bu);

	if(!cstat->permitted) return 0;

	if(bu_get_list_with_working((struct sdirs *)cstat->sdirs, &bu))
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
