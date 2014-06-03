#include "include.h"

struct sdirs *sdirs_alloc(void)
{
	return (struct sdirs *)calloc_w(1, sizeof(struct sdirs), __func__);
}

static int do_lock_dirs(struct sdirs *sdirs, struct conf *conf)
{
	int ret=-1;
	char *lockbase=NULL;
	char *lockfile=NULL;
	if(conf->client_lockdir)
	{
		if(!(sdirs->lockdir=strdup_w(conf->client_lockdir, __func__))
		  || !(lockbase=prepend_s(sdirs->lockdir, conf->cname)))
			goto end;
	}
	else
	{
		if(!(sdirs->lockdir=strdup_w(sdirs->client, __func__))
		  || !(lockbase=strdup_w(sdirs->client, __func__)))
			goto end;
	}
	if(!(lockfile=prepend_s(lockbase, "lockfile"))
	  || !(sdirs->lock=lock_alloc_and_init(lockfile)))
		goto end;
	ret=0;
end:
	free_w(&lockbase);
	free_w(&lockfile);
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
	  || !(sdirs->champlock=prepend_s(sdirs->data, "cc.lock"))
	  || !(sdirs->champsock=prepend_s(sdirs->data, "cc.sock"))
	  || !(sdirs->champlog=prepend_s(sdirs->data, "cc.log"))
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

	if(!(sdirs->base=strdup_w(conf->directory, __func__)))
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
	return -1;
}

void sdirs_free_content(struct sdirs *sdirs)
{
	free_w(&sdirs->base);
        free_w(&sdirs->base);
        free_w(&sdirs->dedup);
        free_w(&sdirs->champlock);
        free_w(&sdirs->champsock);
        free_w(&sdirs->champlog);
        free_w(&sdirs->data);
        free_w(&sdirs->clients);
        free_w(&sdirs->client);

        free_w(&sdirs->working);
        free_w(&sdirs->finishing);
        free_w(&sdirs->current);

        free_w(&sdirs->timestamp);
        free_w(&sdirs->changed);
        free_w(&sdirs->unchanged);
        free_w(&sdirs->cmanifest);
	free_w(&sdirs->phase1data);

	free_w(&sdirs->lockdir);
	lock_free(&sdirs->lock);

	// Legacy directories
	free_w(&sdirs->currentdata);
	free_w(&sdirs->manifest);
	free_w(&sdirs->datadirtmp);
	free_w(&sdirs->phase2data);
	free_w(&sdirs->unchangeddata);
	free_w(&sdirs->cincexc);
	free_w(&sdirs->deltmppath);
}

void sdirs_free(struct sdirs **sdirs)
{
	if(!sdirs || !*sdirs) return;
	sdirs_free_content(*sdirs);

	free_v((void **)sdirs);
}
