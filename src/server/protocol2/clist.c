#include "../../burp.h"
#include "../../alloc.h"
#include "../../conf.h"
#include "../../cstat.h"
#include "../../fsops.h"
#include "../../log.h"
#include "../../prepend.h"
#include "clist.h"

int get_client_list(
	struct cstat **clist,
	const char *cdir,
	struct conf **conf
) {
	int i=0;
	int ret=-1;
	int count=0;
	char *fullpath=NULL;
	char **clients=NULL;
	struct cstat *cnew=NULL;
	const char *clientconfdir=get_string(conf[OPT_CLIENTCONFDIR]);
	if(entries_in_directory_alphasort(
		cdir,
		&clients,
		&count,
		1/*atime*/,
		1/*follow_symlinks*/))
			goto error;
	for(i=0; i<count; i++)
	{
		free_w(&fullpath);
		if(!(fullpath=prepend_s(cdir, clients[i])))
			goto end;
		switch(is_dir_lstat(fullpath))
		{
			case 0: continue;
			case 1: break;
			default: logp("is_dir(%s): %s\n",
				 fullpath, strerror(errno));
					goto error;
		}

		// Have a good entry. Add it to the list.
		if(!(cnew=cstat_alloc())
		  || !(cnew->sdirs=sdirs_alloc()))
			goto error;
		// Cannot just set OPT_CNAME to clients[i] on conf, as it
		// overrides our current settings, which are needed later.
		// Pass clients[i] through.
		if((sdirs_init_from_confs_plus_cname(
		  (struct sdirs *)cnew->sdirs, conf, clients[i])))
			goto error;
		if(cstat_init(cnew, clients[i], clientconfdir))
			goto error;
		cstat_add_to_list(clist, cnew);
		cnew=NULL;
	}
	ret=0;
	goto end;
error:
	cstat_list_free(clist);
end:
	for(i=0; i<count; i++)
		free_w(&(clients[i]));
	free_v((void **)&clients);
	free_w(&fullpath);
	if(cnew)
	{
		sdirs_free((struct sdirs **)&cnew->sdirs);
		cstat_free(&cnew);
	}
	return ret;
}

void clist_free(struct cstat **clist)
{
	struct cstat *c;
	if(!clist || !*clist)
		return;
	for(c=*clist; c; c=c->next)
		sdirs_free((struct sdirs **)&c->sdirs);
	cstat_list_free(clist);
}
