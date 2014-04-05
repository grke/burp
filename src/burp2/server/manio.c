#include "include.h"

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
	if(manio->directory) free(manio->directory);
	if(manio->fpath) free(manio->fpath);
	if(manio->mode) free(manio->mode);
	memset(manio, 0, sizeof(struct manio));
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

void manio_set_protocol(struct manio *manio, enum protocol protocol)
{
	manio->protocol=protocol;
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
	manio_set_protocol(manio, PROTO_BURP2);
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

static char *get_next_fpath_burp1(struct manio *manio)
{
	return strdup(manio->directory);
}

static char *get_next_fpath(struct manio *manio)
{
	static char tmp[32];
	if(manio->protocol==PROTO_BURP1) return get_next_fpath_burp1(manio);
	snprintf(tmp, sizeof(tmp), "%08lX", manio->fcount++);
	return prepend_s(manio->directory, tmp);
}

static int open_next_fpath(struct manio *manio)
{
	char *last_path;
	static struct stat statp;

	last_path=manio->fpath;
	if(!(manio->fpath=get_next_fpath(manio))) return -1;

	if(!strcmp(manio->mode, MANIO_MODE_READ)
	  && lstat(manio->fpath, &statp))
	{
		// It is useful to keep the last valid path when the
		// files have run out.
		free(manio->fpath);
		manio->fpath=last_path;
		return 0;
	}
	if(last_path) free(last_path);

//printf("manio path: %s\n", manio->fpath);

	if(build_path_w(manio->fpath)
	  || !(manio->zp=gzopen_file(manio->fpath, manio->mode)))
		return -1;
	return 0;
}

// Return -1 for error, 0 for stuff read OK, 1 for end of files.
int manio_sbuf_fill(struct manio *manio, struct sbuf *sb, struct blk *blk,
	struct dpth *dpth, struct conf *conf)
{
	int ars;

	while(1)
	{
		if(!manio->zp)
		{
			if(open_next_fpath(manio)) goto error;
			if(!manio->zp) return 1; // No more files to read.
			manio->first_entry=1;
		}
		else
		{
			manio->first_entry=0;
		}
		if((ars=sbuf_fill_from_gzfile(sb, manio->zp, blk,
			dpth?dpth->base_path:NULL, conf))<0) goto error;
		else if(!ars)
			return 0; // Got something.

		// Reached the end of the current file.
		// Maybe there is another file to continue with.
		manio_close(manio);

		// If in burp1 mode, there is only one file, so end.
		if(manio->protocol==PROTO_BURP1) return 1;
	}

error:
	manio_close(manio);
	return -1;
}

static int reset_sig_count_and_close(struct manio *manio)
{
	manio->sig_count=0;
	if(manio_close(manio)) return -1;
	return 0;
}

#define TOCHECK	4
static int manio_find_boundary(const char *msg)
{
	int i;
	int j;
	// I am currently making it look for four of the same consecutive
	// characters in the signature.
	for(i=0; i<16+32-TOCHECK+1; )
	{
		for(j=1; j<TOCHECK; j++)
			if(msg[i]!=msg[i+j]) { i+=j+1; break; }
		if(j==TOCHECK)
			return 1;
	}
	return 0;
}

// After conditions are met, close the file currently being written to.
// Allow the number of signatures to be vary between MANIFEST_SIG_MIN and
// MANIFEST_SIG_MAX. This will hopefully allow fewer candidate manifests
// generated, since the boundary will be able to vary.
static int check_sig_count(struct manio *manio, const char *msg)
{
	manio->sig_count++;

	if(manio->sig_count<MANIFEST_SIG_MIN)
		return 0; // Not yet time to close.

	if(manio->sig_count>=MANIFEST_SIG_MAX)
		return reset_sig_count_and_close(manio); // Time to close.

	// At this point, dynamically decide based on the current msg.
	//if(manio_find_boundary(manio, msg))
	//	return reset_sig_count_and_close(manio); // Time to close.
	return 0;
}

static int write_sig_msg(struct manio *manio, const char *msg)
{
	if(!manio->zp && open_next_fpath(manio)) return -1;
	if(send_msg_zp(manio->zp, CMD_SIG, msg, strlen(msg))) return -1;
	return check_sig_count(manio, msg);
}

static char *sig_to_msg(struct blk *blk, int save_path)
{
	static char msg[128];
	snprintf(msg, sizeof(msg), "%s%s%s",
		blk->weak, blk->strong, save_path?blk->save_path:"");
	return msg;
}

int manio_write_sig(struct manio *manio, struct blk *blk)
{
	return write_sig_msg(manio, sig_to_msg(blk, 0 /* no save_path */));
}

int manio_write_sig_and_path(struct manio *manio, struct blk *blk)
{
	return write_sig_msg(manio, sig_to_msg(blk, 1 /* save_path */));
}

int manio_write_sbuf(struct manio *manio, struct sbuf *sb)
{
	if(!manio->zp && open_next_fpath(manio)) return -1;
	return sbuf_to_manifest(sb, manio->zp);
}

int manio_closed(struct manio *manio)
{
	if(manio->zp || !manio->fpath) return 0;
	return 1;
}
