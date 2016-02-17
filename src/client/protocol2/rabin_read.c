#include "../../burp.h"
#include "../../attribs.h"
#include "../../bfile.h"
#include "../../cntr.h"
#include "../../log.h"
#include "../../sbuf.h"

// Return -1 for error, 0 for could not open file, 1 for success.
int rabin_open_file(struct sbuf *sb, struct asfd *asfd, struct cntr *cntr,
        struct conf **confs)
{
	BFILE *bfd=&sb->protocol2->bfd;
#ifdef HAVE_WIN32
	if(win32_lstat(sb->path.buf, &sb->statp, &sb->winattr))
#else
	if(lstat(sb->path.buf, &sb->statp))
#endif
	{
		// This file is no longer available.
		logw(asfd, cntr, "%s has vanished\n", sb->path.buf);
		return 0;
	}
	if(sbuf_is_metadata(sb))
	{
		// Implement this.
		// Load all of the metadata into a buffer.
		return -1;
	}
	sb->compression=get_int(confs[OPT_COMPRESSION]);
	// Encryption not yet implemented in protocol2.
	//sb->protocol2->encryption=conf->protocol2->encryption_password?1:0;
	if(attribs_encode(sb)) return -1;

	if(bfd->open_for_send(bfd, asfd,
		sb->path.buf, sb->winattr,
		get_int(confs[OPT_ATIME]), cntr, PROTO_2))
	{
		logw(asfd, get_cntr(confs),
			"Could not open %s\n", sb->path.buf);
		return 0;
	}
	return 1;
}

void rabin_close_file(struct sbuf *sb, struct asfd *asfd)
{
	BFILE *bfd;
	if(sbuf_is_metadata(sb))
	{
		// Implement this.
		// Free the buffer.
		return;
	}
	bfd=&sb->protocol2->bfd;
	bfd->close(bfd, asfd);
}

ssize_t rabin_read(struct sbuf *sb, char *buf, size_t bufsize)
{
	BFILE *bfd;
	if(sbuf_is_metadata(sb))
	{
		// Implement this.
		// Place bufsize of the metadata buffer contents into buf.
		return 0;
	}
	bfd=&sb->protocol2->bfd;
	return (ssize_t)bfd->read(bfd, buf, bufsize);
}
