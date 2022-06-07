#include "../burp.h"
#include "fdirs.h"
#include "../alloc.h"
#include "../prepend.h"

struct fdirs *fdirs_alloc(void)
{
	return (struct fdirs *)calloc_w(1, sizeof(struct fdirs), __func__);
}

int fdirs_init(struct fdirs *fdirs,
	struct sdirs *sdirs, const char *realcurrent)
{
	if((fdirs->datadir=prepend_s(sdirs->finishing, "data"))
	 && (fdirs->datadirtmp=prepend_s(sdirs->finishing, "data.tmp"))
	 && (fdirs->manifest=prepend_s(sdirs->finishing, "manifest.gz"))
	 && (fdirs->deletionsfile=prepend_s(sdirs->finishing, "deletions"))
	 && (fdirs->currentdup=prepend_s(sdirs->finishing, "currentdup"))
	 && (fdirs->currentduptmp=prepend_s(sdirs->finishing, "currentdup.tmp"))
	 && (fdirs->currentdupdata=prepend_s(fdirs->currentdup, "data"))
	 && (fdirs->timestamp=prepend_s(sdirs->finishing, "timestamp"))
	 && (fdirs->fullrealcurrent=prepend_s(sdirs->client, realcurrent))
	 && (fdirs->logpath=prepend_s(sdirs->finishing, "log"))
	 && (fdirs->hlinked=prepend_s(sdirs->finishing, "hardlinked"))
	 && (fdirs->hlinkedcurrent=prepend_s(sdirs->current, "hardlinked")))
	{
		return 0;
	}
	return -1;
}

static void fdirs_free_content(struct fdirs *fdirs)
{
	if(!fdirs) return;
	free_w(&fdirs->datadir);
	free_w(&fdirs->datadirtmp);
	free_w(&fdirs->manifest);
	free_w(&fdirs->deletionsfile);
	free_w(&fdirs->currentdup);
	free_w(&fdirs->currentduptmp);
	free_w(&fdirs->currentdupdata);
	free_w(&fdirs->timestamp);
	free_w(&fdirs->fullrealcurrent);
	free_w(&fdirs->logpath);
	free_w(&fdirs->hlinked);
	free_w(&fdirs->hlinkedcurrent);
}

void fdirs_free(struct fdirs **fdirs)
{
	if(!fdirs || !*fdirs) return;
	fdirs_free_content(*fdirs);
	free_v((void **)fdirs);
}
