#include "include.h"

static int compress(const char *src, const char *dst, struct conf **cconfs)
{
	int res;
	int got;
	FILE *mp=NULL;
	gzFile zp=NULL;
	char buf[ZCHUNK];

	if(!(mp=open_file(src, "rb"))
	  || !(zp=gzopen_file(dst, comp_level(cconfs))))
	{
		close_fp(&mp);
		gzclose_fp(&zp);
		return -1;
	}
	while((got=fread(buf, 1, sizeof(buf), mp))>0)
	{
		res=gzwrite(zp, buf, got);
		if(res!=got)
		{
			logp("compressing %s - read %d but wrote %d\n",
				src, got, res);
			close_fp(&mp);
			gzclose_fp(&zp);
			return -1;
		}
	}
	close_fp(&mp);
	return gzclose_fp(&zp); // this can give an error when out of space
}

int compress_file(const char *src, const char *dst, struct conf **cconfs)
{
	char *dsttmp=NULL;
	pid_t pid=getpid();
	char p[12]="";
	snprintf(p, sizeof(p), "%d", (int)pid);

	if(!(dsttmp=prepend(dst, p, strlen(p), 0 /* no slash */)))
		return -1;
	
	// Need to compress the log.
	logp("Compressing %s to %s...\n", src, dst);
	if(compress(src, dsttmp, cconfs)
	// Possible rename race condition is of little consequence here.
	// You will still have the uncompressed log file.
	  || do_rename(dsttmp, dst))
	{
		unlink(dsttmp);
		free(dsttmp);
		return -1;
	}
	// succeeded - get rid of the uncompressed version
	unlink(src);
	free(dsttmp);
	return 0;
}

int compress_filename(const char *d,
	const char *file, const char *zfile, struct conf **cconfs)
{
	char *fullfile=NULL;
	char *fullzfile=NULL;
	if(!(fullfile=prepend_s(d, file))
	  || !(fullzfile=prepend_s(d, zfile))
	  || compress_file(fullfile, fullzfile, cconfs))
	{
		if(fullfile) free(fullfile);
		if(fullzfile) free(fullzfile);
		return -1;
	}
	return 0;
}
