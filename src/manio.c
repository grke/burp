#include <stdio.h>
#include <stdlib.h>
#include <malloc.h>
#include <string.h>

#include "log.h"
#include "msg.h"
#include "manio.h"
#include "handy.h"
#include "sbuf.h"
#include "cmd.h"
#include "conf.h"
#include "dpth.h"

#define MANIO_MODE_READ		"rb"
#define MANIO_MODE_WRITE	"wb"

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
	manio_close(manio);
	if(manio->directory) { free(manio->directory); manio->directory=NULL; }
	if(manio->fpath) { free(manio->fpath); manio->fpath=NULL; }
	if(manio->mode) { free(manio->mode); manio->mode=NULL; }
	manio->fcount=0;
	manio->sig_count=0;
}

int manio_close(struct manio *manio)
{
	return gzclose_fp(&(manio->zp));
}

void manio_free(struct manio *manio)
{
	if(!manio) return;
	manio_free_contents(manio);
	free(manio);
}

static int manio_set_mode(struct manio *manio, const char *mode)
{
	if(manio_close(manio)) return -1;
	if(manio->mode) free(manio->mode);
	if(!(manio->mode=strdup(mode)))
	{
		log_out_of_memory(__FUNCTION__);
		return -1;
	}
	manio->fcount=0;
	return 0;
}

int manio_set_mode_read(struct manio *manio)
{
	return manio_set_mode(manio, MANIO_MODE_READ);
}

int manio_set_mode_write(struct manio *manio)
{
	return manio_set_mode(manio, MANIO_MODE_WRITE);
}

static int manio_init(struct manio *manio, const char *directory, const char *mode)
{
	manio_free_contents(manio);
	if(!(manio->directory=strdup(directory)))
	{
		log_out_of_memory(__FUNCTION__);
		return -1;
	}
	if(manio_set_mode(manio, mode)) return -1;
	return 0;
}

int manio_init_read(struct manio *manio, const char *directory)
{
	return manio_init(manio, directory, MANIO_MODE_READ);
}

int manio_init_write(struct manio *manio, const char *directory)
{
	return manio_init(manio, directory, MANIO_MODE_WRITE);
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

	if(!strcmp(manio->mode, MANIO_MODE_READ)
	  && lstat(manio->fpath, &statp)) return 0;

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
		manio_close(manio);
	}

error:
	manio_close(manio);
	return -1;
}

// Close the current file after SIG_MAX entries are written.
static int check_sig_count(struct manio *manio)
{
	if(++manio->sig_count<SIG_MAX) return 0;
	manio->sig_count=0;
	if(manio_close(manio)) return -1;
	return 0;
}

int manio_write_sig(struct manio *manio, struct blk *blk)
{
	if(!manio->zp && open_next_fpath(manio)) return -1;
	// FIX THIS: check for errors
	// FIX THIS: get rid of strlen()
	// FIX THIS too
	gzprintf(manio->zp, "%c%04X%s%s\n", CMD_SIG,
		strlen(blk->weak)+strlen(blk->strong),
		blk->weak, blk->strong);
	return check_sig_count(manio);
}

int manio_write_sig_and_path(struct manio *manio, struct blk *blk)
{
	if(!manio->zp && open_next_fpath(manio)) return -1;
	// FIX THIS: check for errors
	// FIX THIS: get rid of strlen()
	gzprintf(manio->zp, "%c%04X%s%s%s\n", CMD_SIG,
		strlen(blk->weak)+strlen(blk->strong)+strlen(blk->save_path),
		blk->weak, blk->strong, blk->save_path);
	return check_sig_count(manio);
}

int manio_write_sbuf(struct manio *manio, struct sbuf *sb)
{
	if(!manio->zp && open_next_fpath(manio)) return -1;
	return sbuf_to_manifest(sb, manio->zp);
}
