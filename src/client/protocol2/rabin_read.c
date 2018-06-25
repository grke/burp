#include "../../burp.h"
#include "../../alloc.h"
#include "../../attribs.h"
#include "../../bfile.h"
#include "../../cntr.h"
#include "../../log.h"
#include "../../sbuf.h"
#include "../extrameta.h"
#include "rabin_read.h"

static char *meta_buffer=NULL;
static size_t meta_buffer_len=0;
static char *mp=NULL;

static int rabin_close_file_extrameta(struct sbuf *sb)
{
	free_w(&meta_buffer);
	meta_buffer_len=0;
	mp=NULL;
	sb->protocol2->bfd.mode=BF_CLOSED;
	return 0;
}

// Return -1 for error, 0 for could not get data, 1 for success.
static int rabin_open_file_extrameta(struct sbuf *sb, struct asfd *asfd,
	struct cntr *cntr)
{
	// Load all of the metadata into a buffer.
	rabin_close_file_extrameta(sb);
	if(get_extrameta(asfd,
#ifdef HAVE_WIN32
		NULL,
#endif
		sb->path.buf, S_ISDIR(sb->statp.st_mode),
		&meta_buffer, &meta_buffer_len, cntr))
			return -1;
	if(!meta_buffer)
		return 0;
	mp=meta_buffer;
	sb->protocol2->bfd.mode=BF_READ;
	return 1;
}

static ssize_t rabin_read_extrameta(char *buf, size_t bufsize)
{
	// Place bufsize of the meta buffer contents into buf.
	size_t to_read=meta_buffer_len;
	if(!meta_buffer_len)
		return 0;
	if(bufsize<meta_buffer_len)
		to_read=bufsize;
	memcpy(buf, mp, to_read);
	meta_buffer_len-=to_read;
	mp+=to_read;
	return (ssize_t)to_read;
}

// Return -1 for error, 0 for could not open file, 1 for success.
int rabin_open_file(struct sbuf *sb, struct asfd *asfd, struct cntr *cntr,
        struct conf **confs)
{
	struct BFILE *bfd=&sb->protocol2->bfd;
#ifdef HAVE_WIN32
	if(win32_lstat(sb->path.buf, &sb->statp, &sb->winattr))
#else
	if(lstat(sb->path.buf, &sb->statp))
#endif
	{
		// This file is no longer available.
		logw(asfd, cntr, "%s has vanished\n",
			iobuf_to_printable(&sb->path));
		return 0;
	}
	sb->compression=get_int(confs[OPT_COMPRESSION]);
	// Encryption not yet implemented in protocol2.
	//sb->encryption=conf->protocol2->encryption_password?1:0;
	sb->encryption=ENCRYPTION_NONE;
	if(attribs_encode(sb)) return -1;
	if(sbuf_is_metadata(sb))
		return rabin_open_file_extrameta(sb, asfd, cntr);

	if(bfd->open_for_send(bfd, asfd,
		sb->path.buf, sb->winattr,
		get_int(confs[OPT_ATIME]), cntr, PROTO_2))
	{
		logw(asfd, get_cntr(confs),
			"Could not open %s\n",
			iobuf_to_printable(&sb->path));
		return 0;
	}
	return 1;
}

int rabin_close_file(struct sbuf *sb, struct asfd *asfd)
{
	struct BFILE *bfd;
	if(sbuf_is_metadata(sb))
		return rabin_close_file_extrameta(sb);
	bfd=&sb->protocol2->bfd;
	return bfd->close(bfd, asfd);
}

ssize_t rabin_read(struct sbuf *sb, char *buf, size_t bufsize)
{
	struct BFILE *bfd;
	if(sbuf_is_metadata(sb))
		return rabin_read_extrameta(buf, bufsize);
	bfd=&sb->protocol2->bfd;
	return (ssize_t)bfd->read(bfd, buf, bufsize);
}
