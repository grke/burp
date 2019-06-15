#include "../burp.h"
#include "sdirs.h"
#include "../alloc.h"
#include "../conf.h"
#include "../fsops.h"
#include "../lock.h"
#include "../log.h"
#include "../prepend.h"
#include "timestamp.h"

#define RELINK_DIR	"relink"

struct sdirs *sdirs_alloc(void)
{
	return (struct sdirs *)calloc_w(1, sizeof(struct sdirs), __func__);
}

static int do_lock_dirs(struct sdirs *sdirs,
	const char *cname, const char *conf_lockdir)
{
	int ret=-1;
	char *lockbase=NULL;
	char *lockfile=NULL;
	if(conf_lockdir)
	{
		if(!(sdirs->lockdir=strdup_w(conf_lockdir, __func__))
		  || !(lockbase=prepend_s(sdirs->lockdir, cname)))
			goto end;
	}
	else
	{
		if(!(sdirs->lockdir=strdup_w(sdirs->client, __func__))
		  || !(lockbase=strdup_w(sdirs->client, __func__)))
			goto end;
	}
	if(!(lockfile=prepend_s(lockbase, "lockfile"))
	  || !(sdirs->lock_storage_for_write=lock_alloc_and_init(lockfile)))
		goto end;
	ret=0;
end:
	free_w(&lockbase);
	free_w(&lockfile);
	return ret;
}

static int free_prepend_s(char **dst, const char *a, const char *b)
{
	free_w(dst);
	return !(*dst=prepend_s(a, b));
}

int sdirs_get_real_manifest(struct sdirs *sdirs, enum protocol protocol)
{
	return free_prepend_s(&sdirs->rmanifest,
		sdirs->rworking, protocol==PROTO_1?"manifest.gz":"manifest");
}

int sdirs_get_real_working_from_symlink(struct sdirs *sdirs)
{
	char real[256]="";
	if(readlink_w(sdirs->working, real, sizeof(real))<0)
	{
		logp("Could not readlink %s: %s\n",
			sdirs->working, strerror(errno));
		return -1;
	}
	if(free_prepend_s(&sdirs->rworking, sdirs->client, real)
	  || free_prepend_s(&sdirs->treepath,
		sdirs->rworking, DATA_DIR "/" TREE_DIR)
	  || free_prepend_s(&sdirs->relink, sdirs->rworking, RELINK_DIR))
		return -1;
	return 0;
}

int sdirs_create_real_working(
	struct sdirs *sdirs,
	uint64_t bno,
	const char *timestamp_format
) {
	char tstmp[64]="";
	char fname[64]="";

	if(build_path_w(sdirs->working))
		return -1;
	if(timestamp_get_new(bno,
		tstmp, sizeof(tstmp), fname, sizeof(fname), timestamp_format)
	  || free_prepend_s(&sdirs->rworking, sdirs->client, fname)
	  || free_prepend_s(&sdirs->treepath,
		sdirs->rworking, DATA_DIR "/" TREE_DIR)
	  || free_prepend_s(&sdirs->relink, sdirs->rworking, RELINK_DIR))
		return -1;

	// Add the working symlink before creating the directory.
	// This is because bedup checks the working symlink before
	// going into a directory. If the directory got created first,
	// bedup might go into it in the moment before the symlink
	// gets added.
	if(do_symlink(fname, sdirs->working))
		// relative link to the real work dir
	{
		logp("could not point working symlink to: %s\n",
			sdirs->rworking);
		return -1;
	}
	if(mkdir(sdirs->rworking, 0777))
	{
		logp("could not mkdir for next backup: %s\n", sdirs->rworking);
		unlink(sdirs->working);
		return -1;
	}
	if(timestamp_write(sdirs->timestamp, tstmp))
	{
		logp("unable to write timestamp %s to %s\n",
			tstmp, sdirs->timestamp);
		return -1;
	}

	return 0;
}

static int do_common_dirs(struct sdirs *sdirs, const char *manual_delete)
{
	if(!(sdirs->created=prepend_s(sdirs->client, ".created"))
	  || !(sdirs->command=prepend_s(sdirs->client, ".command"))
	  || !(sdirs->working=prepend_s(sdirs->client, "working"))
	  || !(sdirs->finishing=prepend_s(sdirs->client, "finishing"))
	  || !(sdirs->current=prepend_s(sdirs->client, "current"))
	  || !(sdirs->currenttmp=prepend_s(sdirs->client, "current.tmp"))
	  || !(sdirs->timestamp=prepend_s(sdirs->working, "timestamp"))
	  || !(sdirs->phase1data=prepend_s(sdirs->working, "phase1.gz"))
	  || !(sdirs->changed=prepend_s(sdirs->working, "changed"))
	  || !(sdirs->unchanged=prepend_s(sdirs->working, "unchanged")))
		return -1;
	if(manual_delete)
	{
		if(!(sdirs->deleteme=strdup_w(manual_delete, __func__)))
			return -1;
	}
	else
	{
		if(!(sdirs->deleteme=prepend_s(sdirs->client, "deleteme")))
			return -1;
	}
	return 0;
}

// Maybe should be in a protocol1 directory.
static int do_protocol1_dirs(struct sdirs *sdirs, const char *cname,
	const char *manual_delete)
{
	if(!(sdirs->clients=strdup_w(sdirs->base, __func__))
	  || !(sdirs->client=prepend_s(sdirs->clients, cname))
	  || do_common_dirs(sdirs, manual_delete)
	  || !(sdirs->currentdata=prepend_s(sdirs->current, DATA_DIR))
	  || !(sdirs->manifest=prepend_s(sdirs->working, "manifest.gz"))
	  || !(sdirs->datadirtmp=prepend_s(sdirs->working, "data.tmp"))
	  || !(sdirs->cmanifest=prepend_s(sdirs->current, "manifest.gz"))
	  || !(sdirs->cincexc=prepend_s(sdirs->current, "incexc"))
	  || !(sdirs->deltmppath=prepend_s(sdirs->working, "deltmppath")))
			return -1;
	// sdirs->rworking gets set later.
	// sdirs->treepath gets set later.
	// sdirs->relink gets set later.
	return 0;
}

static int do_protocol2_dirs(struct sdirs *sdirs,
	const char *cname, const char *dedup_group, const char *manual_delete)
{
	if(!dedup_group)
	{
		logp("dedup_group unset in %s\n", __func__);
		return -1;
	}
	if(!(sdirs->dedup=prepend_s(sdirs->base, dedup_group))
	  || !(sdirs->clients=prepend_s(sdirs->dedup, "clients"))
	  || !(sdirs->client=prepend_s(sdirs->clients, cname))
	  || !(sdirs->dindex=prepend_s(sdirs->client, "dindex"))
	  || !(sdirs->dfiles=prepend_s(sdirs->client, "dfiles"))
	  || do_common_dirs(sdirs, manual_delete)
	  || !(sdirs->data=prepend_s(sdirs->dedup, DATA_DIR))
	  || !(sdirs->cfiles=prepend_s(sdirs->data, "cfiles"))
	  || !(sdirs->global_sparse=prepend_s(sdirs->data, "sparse"))
	  || !(sdirs->champlock=prepend_s(sdirs->data, "cc.lock"))
	  || !(sdirs->champsock=prepend_s(sdirs->data, "cc.sock"))
	  || !(sdirs->champlog=prepend_s(sdirs->data, "cc.log"))
	  || !(sdirs->champ_dindex_lock=prepend_s(sdirs->data, "dindex.lock"))
	  || !(sdirs->manifest=prepend_s(sdirs->working, "manifest"))
	  || !(sdirs->cmanifest=prepend_s(sdirs->current, "manifest")))
		return -1;
	// sdirs->rworking gets set later.
	// sdirs->rmanifest gets set later.
	return 0;
}

int sdirs_init_from_confs(struct sdirs *sdirs, struct conf **confs)
{
	return sdirs_init(
		sdirs,
		get_protocol(confs),
		get_string(confs[OPT_DIRECTORY]),
		get_string(confs[OPT_CNAME]),
		get_string(confs[OPT_CLIENT_LOCKDIR]),
		get_string(confs[OPT_DEDUP_GROUP]),
		get_string(confs[OPT_MANUAL_DELETE])
	);
}

int sdirs_init(struct sdirs *sdirs, enum protocol protocol,
	const char *directory, const char *cname, const char *conf_lockdir,
	const char *dedup_group, const char *manual_delete)
{
	if(!directory)
	{
		logp("directory unset in %s\n", __func__);
		goto error;
	}

	if(!(sdirs->base=strdup_w(directory, __func__)))
		goto error;

	sdirs->protocol=protocol;

	if(protocol==PROTO_1)
	{
		if(do_protocol1_dirs(sdirs, cname, manual_delete))
			goto error;
	}
	else
	{
		if(do_protocol2_dirs(sdirs, cname, dedup_group, manual_delete))
			goto error;
	}

	if(do_lock_dirs(sdirs, cname, conf_lockdir)) goto error;

	return 0;
error:
	return -1;
}

void sdirs_free_content(struct sdirs *sdirs)
{
        free_w(&sdirs->base);
        free_w(&sdirs->dedup);
        free_w(&sdirs->champlock);
        free_w(&sdirs->champsock);
        free_w(&sdirs->champlog);
        free_w(&sdirs->champ_dindex_lock);
        free_w(&sdirs->data);
        free_w(&sdirs->clients);
        free_w(&sdirs->client);
        free_w(&sdirs->created);
        free_w(&sdirs->command);

        free_w(&sdirs->working);
        free_w(&sdirs->rworking);
        free_w(&sdirs->finishing);
        free_w(&sdirs->current);
        free_w(&sdirs->currenttmp);
        free_w(&sdirs->deleteme);
        free_w(&sdirs->dindex);
        free_w(&sdirs->dfiles);
        free_w(&sdirs->cfiles);
        free_w(&sdirs->global_sparse);

        free_w(&sdirs->timestamp);
        free_w(&sdirs->changed);
        free_w(&sdirs->unchanged);
	free_w(&sdirs->manifest);
	free_w(&sdirs->rmanifest);
        free_w(&sdirs->cmanifest);
	free_w(&sdirs->phase1data);

	free_w(&sdirs->lockdir);
	lock_free(&sdirs->lock_storage_for_write);

	// Protocol1 directories.
	free_w(&sdirs->currentdata);
	free_w(&sdirs->datadirtmp);
	free_w(&sdirs->cincexc);
	free_w(&sdirs->deltmppath);
	free_w(&sdirs->treepath);
	free_w(&sdirs->relink);
}

void sdirs_free(struct sdirs **sdirs)
{
	if(!sdirs || !*sdirs) return;
	sdirs_free_content(*sdirs);

	free_v((void **)sdirs);
}
