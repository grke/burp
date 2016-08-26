#include "../burp.h"
#include "../alloc.h"
#include "../asfd.h"
#include "../async.h"
#include "../fsops.h"
#include "../fzp.h"
#include "../log.h"
#include "../prepend.h"
#include "compress.h"

char *comp_level(int compression)
{
	static char comp[8]="";
	snprintf(comp, sizeof(comp), "wb%d", compression);
	return comp;
}

static int bcompress(const char *src, const char *dst, int compression)
{
	int res;
	int got;
	struct fzp *sfzp=NULL;
	struct fzp *dfzp=NULL;
	char buf[ZCHUNK];

	if(!(sfzp=fzp_open(src, "rb"))
	  || !(dfzp=fzp_gzopen(dst, comp_level(compression))))
		goto error;
	while((got=fzp_read(sfzp, buf, sizeof(buf)))>0)
	{
		res=fzp_write(dfzp, buf, got);
		if(res!=got)
		{
			logp("compressing %s - read %d but wrote %d\n",
				src, got, res);
			goto error;
		}
	}
	fzp_close(&sfzp);
	return fzp_close(&dfzp);
error:
	fzp_close(&sfzp);
	fzp_close(&dfzp);
	return -1;
}

int compress_file(const char *src, const char *dst, int compression)
{
	int ret=-1;
	char *dsttmp=NULL;
	pid_t pid=getpid();
	char p[12]="";
	snprintf(p, sizeof(p), "%d", (int)pid);

	if(!(dsttmp=prepend(dst, p)))
		return -1;

	// Need to compress the log.
	logp("Compressing %s to %s...\n", src, dst);
	if(bcompress(src, dsttmp, compression)
	// Possible rename race condition is of little consequence here.
	// You will still have the uncompressed log file.
	  || do_rename(dsttmp, dst))
	{
		unlink(dsttmp);
		goto end;
	}
	// succeeded - get rid of the uncompressed version
	unlink(src);
	ret=0;
end:
	free_w(&dsttmp);
	return ret;
}

int compress_filename(const char *d,
	const char *file, const char *zfile, int compression)
{
	char *fullfile=NULL;
	char *fullzfile=NULL;
	if(!(fullfile=prepend_s(d, file))
	  || !(fullzfile=prepend_s(d, zfile))
	  || compress_file(fullfile, fullzfile, compression))
	{
		free_w(&fullfile);
		free_w(&fullzfile);
		return -1;
	}
	return 0;
}
