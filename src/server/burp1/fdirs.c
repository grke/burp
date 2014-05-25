#include "include.h"

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
	 && (fdirs->hlinkedpath=prepend_s(fdirs->currentdup, "hardlinked")))
		return 0;
	return -1;
}

void fdirs_free(struct fdirs *fdirs)
{
	if(!fdirs) return;
	if(fdirs->datadir) free(fdirs->datadir);
	if(fdirs->datadirtmp) free(fdirs->datadirtmp);
	if(fdirs->manifest) free(fdirs->manifest);
	if(fdirs->deletionsfile) free(fdirs->deletionsfile);
	if(fdirs->currentdup) free(fdirs->currentdup);
	if(fdirs->currentduptmp) free(fdirs->currentduptmp);
	if(fdirs->currentdupdata) free(fdirs->currentdupdata);
	if(fdirs->timestamp) free(fdirs->timestamp);
	if(fdirs->fullrealcurrent) free(fdirs->fullrealcurrent);
	if(fdirs->logpath) free(fdirs->logpath);
	if(fdirs->hlinkedpath) free(fdirs->hlinkedpath);
}
