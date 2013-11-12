#include "include.h"

struct sdirs *sdirs_alloc(void)
{
        struct sdirs *sdirs;
        if((sdirs=(struct sdirs *)calloc(1, sizeof(struct sdirs))))
		return sdirs;
	log_out_of_memory(__FUNCTION__);
	return NULL;
}

int sdirs_init(struct sdirs *sdirs, struct config *conf, const char *client)
{
	char *client_lockdir;

	if(!conf->directory)
	{
		logp("conf->directory unset in %s\n", __FUNCTION__);
		goto error;
	}
	if(!conf->dedup_group)
	{
		logp("conf->dedup_group unset in %s\n", __FUNCTION__);
		goto error;
	}

	if(!(sdirs->base=strdup(conf->directory))
	  || !(sdirs->dedup=prepend_str(sdirs->base, conf->dedup_group))
	  || !(sdirs->data=prepend_str(sdirs->dedup, "data"))
	  || !(sdirs->clients=prepend_str(sdirs->dedup, "clients"))
	  || !(sdirs->client=prepend_str(sdirs->clients, client)))
		goto error;

	if(!(sdirs->working=prepend_str(sdirs->client, "working"))
	  || !(sdirs->finishing=prepend_str(sdirs->client, "finishing"))
	  || !(sdirs->current=prepend_str(sdirs->client, "current")))
		goto error;

	if(!(sdirs->timestamp=prepend_str(sdirs->working, "timestamp"))
	  || !(sdirs->changed=prepend_str(sdirs->working, "changed"))
	  || !(sdirs->unchanged=prepend_str(sdirs->working, "unchanged"))
	  || !(sdirs->cmanifest=prepend_str(sdirs->current, "manifest")))
		goto error;

	if(!(client_lockdir=conf->client_lockdir))
		client_lockdir=sdirs->client;
	if(!(sdirs->lock=strdup(client_lockdir))
	  || !(sdirs->lockbase=prepend_str(sdirs->lock, client))
	  || !(sdirs->lockfile=prepend_str(sdirs->lockbase, "lockfile")))
		goto error;

	return 0;
error:
	sdirs_free(sdirs);
	return -1;
}

void sdirs_free(struct sdirs *sdirs)
{
	if(!sdirs) return;

        if(sdirs->base) free(sdirs->base);
        if(sdirs->dedup) free(sdirs->dedup);
        if(sdirs->data) free(sdirs->data);
        if(sdirs->clients) free(sdirs->clients);
        if(sdirs->client) free(sdirs->client);

        if(sdirs->working) free(sdirs->working);
        if(sdirs->finishing) free(sdirs->finishing);
        if(sdirs->current) free(sdirs->current);

        if(sdirs->timestamp) free(sdirs->timestamp);
        if(sdirs->changed) free(sdirs->changed);
        if(sdirs->unchanged) free(sdirs->unchanged);
        if(sdirs->cmanifest) free(sdirs->cmanifest);

        if(sdirs->lock) free(sdirs->lock);
        if(sdirs->lockbase) free(sdirs->lockbase);
        if(sdirs->lockfile) free(sdirs->lockfile);

	free(sdirs);
	sdirs=NULL;
}
