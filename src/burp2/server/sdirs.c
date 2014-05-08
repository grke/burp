#include "include.h"

struct sdirs *sdirs_alloc(void)
{
	struct sdirs *sdirs=NULL;
	if(!(sdirs=(struct sdirs *)calloc(1, sizeof(struct sdirs))))
		log_out_of_memory(__func__);
	return sdirs;
}

static int do_lock_dirs(struct sdirs *sdirs, struct conf *conf)
{
	int ret=-1;
	char *lockbase=NULL;
	char *lockfile=NULL;
	if(conf->client_lockdir)
	{
		if(!(sdirs->lockdir=strdup(conf->client_lockdir))
		  || !(lockbase=prepend_s(sdirs->lockdir, conf->cname)))
			goto end;
	}
	else
	{
		if(!(sdirs->lockdir=strdup(sdirs->client))
		  || !(lockbase=strdup(sdirs->client)))
			goto end;
	}
	if(!(lockfile=prepend_s(lockbase, "lockfile"))
	  || !(sdirs->lock=lock_alloc_and_init(lockfile)))
		goto end;
	ret=0;
end:
	if(lockbase) free(lockbase);
	if(lockfile) free(lockfile);
	return ret;
}

// Maybe should be in a burp1 directory.
static int do_burp1_dirs(struct sdirs *sdirs, struct conf *conf)
{
	if(!(sdirs->client=prepend_s(sdirs->base, conf->cname))
	  || !(sdirs->working=prepend_s(sdirs->client, "working"))
	  || !(sdirs->finishing=prepend_s(sdirs->client, "finishing"))
	  || !(sdirs->current=prepend_s(sdirs->client, "current"))
	  || !(sdirs->currentdata=prepend_s(sdirs->current, "data"))
	  || !(sdirs->timestamp=prepend_s(sdirs->working, "timestamp"))
	  || !(sdirs->manifest=prepend_s(sdirs->working, "manifest.gz"))
	  || !(sdirs->datadirtmp=prepend_s(sdirs->working, "data.tmp"))
	  || !(sdirs->phase1data=prepend_s(sdirs->working, "phase1.gz"))
	  || !(sdirs->phase2data=prepend_s(sdirs->working, "phase2"))
	  || !(sdirs->unchangeddata=prepend_s(sdirs->working, "unchanged"))
	  || !(sdirs->unchangeddata=prepend_s(sdirs->working, "unchanged"))
	  || !(sdirs->cmanifest=prepend_s(sdirs->current, "manifest.gz"))
	  || !(sdirs->cincexc=prepend_s(sdirs->current, "incexc"))
	  || !(sdirs->deltmppath=prepend_s(sdirs->working, "deltmppath")))
		return -1;
	return 0;
}

static int do_v2_dirs(struct sdirs *sdirs, struct conf *conf)
{
	if(!conf->dedup_group)
	{
		logp("conf->dedup_group unset in %s\n", __func__);
		return -1;
	}
	if(!(sdirs->dedup=prepend_s(sdirs->base, conf->dedup_group))
	  || !(sdirs->data=prepend_s(sdirs->dedup, "data"))
	  || !(sdirs->champlock=prepend_s(sdirs->dedup, "cc.lock"))
	  || !(sdirs->champsock=prepend_s(sdirs->dedup, "cc.sock"))
	  || !(sdirs->champlog=prepend_s(sdirs->dedup, "cc.log"))
	  || !(sdirs->clients=prepend_s(sdirs->dedup, "clients"))
	  || !(sdirs->client=prepend_s(sdirs->clients, conf->cname))
	  || !(sdirs->working=prepend_s(sdirs->client, "working"))
	  || !(sdirs->finishing=prepend_s(sdirs->client, "finishing"))
	  || !(sdirs->current=prepend_s(sdirs->client, "current"))
	  || !(sdirs->timestamp=prepend_s(sdirs->working, "timestamp"))
	  || !(sdirs->changed=prepend_s(sdirs->working, "changed"))
	  || !(sdirs->unchanged=prepend_s(sdirs->working, "unchanged"))
	  || !(sdirs->cmanifest=prepend_s(sdirs->current, "manifest"))
	  || !(sdirs->phase1data=prepend_s(sdirs->working, "phase1.gz")))
		return -1;
	return 0;
}

extern int sdirs_init(struct sdirs *sdirs, struct conf *conf)
{
	if(!conf->directory)
	{
		logp("conf->directory unset in %s\n", __func__);
		goto error;
	}

	if(!(sdirs->base=strdup(conf->directory)))
		goto error;

	if(conf->protocol==PROTO_BURP1)
	{
		if(do_burp1_dirs(sdirs, conf)) goto error;
	}
	else
	{
		if(do_v2_dirs(sdirs, conf)) goto error;
	}

	if(do_lock_dirs(sdirs, conf)) goto error;

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
        if(sdirs->champlock) free(sdirs->champlock);
        if(sdirs->champsock) free(sdirs->champsock);
        if(sdirs->champlog) free(sdirs->champlog);
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
	if(sdirs->phase1data) free(sdirs->phase1data);

	if(sdirs->lockdir) free(sdirs->lockdir);
	lock_free(&sdirs->lock);

	// Legacy directories
	if(sdirs->currentdata) free(sdirs->currentdata);
	if(sdirs->manifest) free(sdirs->manifest);
	if(sdirs->datadirtmp) free(sdirs->datadirtmp);
	if(sdirs->phase2data) free(sdirs->phase2data);
	if(sdirs->unchangeddata) free(sdirs->unchangeddata);
	if(sdirs->cincexc) free(sdirs->cincexc);
	if(sdirs->deltmppath) free(sdirs->deltmppath);

	free(sdirs);
	sdirs=NULL;
}
