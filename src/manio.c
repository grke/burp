#include <stdio.h>
#include <stdlib.h>
#include <malloc.h>
#include <string.h>

#include "log.h"
#include "msg.h"
#include "manio.h"
#include "handy.h"
#include "sbuf.h"

struct manio *manio_alloc(void)
{
	struct manio *m=NULL;
	if(!(m=(struct manio *)calloc(1, sizeof(struct manio))))
		log_out_of_memory(__FUNCTION__);
	return m;
}

static void manio_free_contents(struct manio *manio)
{
	if(!manio) return;
	if(manio->directory) { free(manio->directory); manio->directory=NULL; }
	if(manio->fpath) { free(manio->fpath); manio->fpath=NULL; }
	if(manio->mode) { free(manio->mode); manio->mode=NULL; }
	gzclose_fp(&(manio->zp));
	manio->fcount=0;
}

void manio_free(struct manio *manio)
{
	if(!manio) return;
	manio_free_contents(manio);
	free(manio);
}

static int manio_init(struct manio *manio, const char *directory, const char *mode)
{
	manio_free_contents(manio);
	if(!(manio->directory=strdup(directory))
	  || !(manio->mode=strdup(mode)))
	{
		log_out_of_memory(__FUNCTION__);
		return -1;
	}
	return 0;
}

int manio_init_read(struct manio *manio, const char *directory)
{
	return manio_init(manio, directory, "rb");
}

int manio_init_write(struct manio *manio, const char *directory)
{
	// FIX THIS
	return -1;
	//return manio_init(manio, directory, ???);
}

static int get_next_fpath(struct manio *manio)
{
	static char tmp[32];
	snprintf(tmp, sizeof(tmp), "%08lX", manio->fcount++);
	if(manio->fpath) free(manio->fpath);
	return !(manio->fpath=prepend_s(manio->directory, tmp, sizeof(tmp)));
}

static int open_next_fpath(struct manio *manio)
{
	static struct stat statp;

	if(get_next_fpath(manio)) return -1;

	if(lstat(manio->fpath, &statp)) return 0;

	if(build_path_w(manio->fpath)
	  || !(manio->zp=gzopen_file(manio->fpath, manio->mode)))
		return -1;
	return 0;
}

// Return -1 for error, 0 for stuff read OK, 1 for end of files.
int manio_sbuf_fill(struct manio *manio, struct sbuf *sb, struct blk *blk, struct dpth *dpth, struct config *conf)
{
	int ars;

	while(1)
	{
		if(!manio->zp)
		{
			if(open_next_fpath(manio)) goto error;
			if(!manio->zp) return 1; // No more files to read.
		}
		if((ars=sbuf_fill_from_gzfile(sb,
			manio->zp, blk, dpth, conf))<0) goto error;
		else if(!ars)
			return 0; // Got something.

		// Reached the end of the current file.
		// Maybe there is another file to continue with.
		gzclose_fp(&(manio->zp));
	}

error:
	gzclose_fp(&(manio->zp));
	return -1;
}
