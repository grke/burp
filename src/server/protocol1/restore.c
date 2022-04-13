#include "../../burp.h"
#include "../../alloc.h"
#include "../../asfd.h"
#include "../../async.h"
#include "../../bu.h"
#include "../../cmd.h"
#include "../../cntr.h"
#include "../../handy.h"
#include "../../hexmap.h"
#include "../../log.h"
#include "../../prepend.h"
#include "../../protocol1/handy.h"
#include "../../server/protocol1/backup_phase4.h"
#include "../../server/protocol1/link.h"
#include "../../server/protocol1/zlibio.h"
#include "../../sbuf.h"
#include "../../slist.h"
#include "../sdirs.h"
#include "dpth.h"
#include "restore.h"

#include <librsync.h>

static int create_zero_length_file(const char *path)
{
	int ret=0;
	struct fzp *dest;
	if(!(dest=fzp_open(path, "wb")))
		ret=-1;
	ret|=fzp_close(&dest);
	return ret;
}

static int inflate_or_link_oldfile(struct asfd *asfd, const char *oldpath,
	const char *infpath, struct conf **cconfs, int compression)
{
	int ret=0;
	struct stat statp;

	if(lstat(oldpath, &statp))
	{
		logp("could not lstat %s\n", oldpath);
		return -1;
	}

	if(dpth_protocol1_is_compressed(compression, oldpath))
	{
		//logp("inflating...\n");

		if(!statp.st_size)
		{
			// Empty file - cannot inflate.
			logp("asked to inflate zero length file: %s\n",
				oldpath);
			return create_zero_length_file(infpath);
		}

		if((ret=zlib_inflate(asfd, oldpath, infpath, get_cntr(cconfs))))
			logp("zlib_inflate returned: %d\n", ret);
	}
	else
	{
		// Not compressed - just hard link it.
		if(do_link(oldpath, infpath, &statp, cconfs,
			1 /* allow overwrite of infpath */))
				return -1;
	}
	return ret;
}

static int do_send_file(struct asfd *asfd, struct sbuf *sb,
	int patches, const char *best, struct cntr *cntr)
{
	enum send_e ret=SEND_FATAL;
	struct BFILE bfd;
	uint64_t bytes=0; // Unused.

	bfile_init(&bfd, 0, cntr);
	if(bfd.open_for_send(&bfd, asfd, best, sb->winattr,
		1 /* no O_NOATIME */, cntr))
			return SEND_FATAL;
	if(asfd->write(asfd, &sb->path))
		ret=SEND_FATAL;
	else if(patches)
	{
		// If we did some patches, the resulting file
		// is not gzipped. Gzip it during the send.
		ret=send_whole_file_gzl(
			asfd,
			sb->protocol1->datapth.buf,
			/*quick_read*/1,
			&bytes,
			/*encpassword*/NULL,
			cntr,
			/*compression*/9,
			&bfd,
			/*extrameta*/NULL,
			/*elen*/0,
			/*key_deriv*/ENCRYPTION_UNSET,
			/*salt*/0
		);
	}
	else
	{
		// If it was encrypted, it may or may not have been compressed
		// before encryption. Send it as it as, and let the client
		// sort it out.
		if(sbuf_is_encrypted(sb))
		{
			ret=send_whole_filel(asfd,
#ifdef HAVE_WIN32
				sb->path.cmd
#endif
				sb->protocol1->datapth.buf,
				1, &bytes, cntr, &bfd, NULL, 0);
		}
		// It might have been stored uncompressed. Gzip it during
		// the send. If the client knew what kind of file it would be
		// receiving, this step could disappear.
		else if(!dpth_protocol1_is_compressed(sb->compression,
			sb->protocol1->datapth.buf))
		{
			ret=send_whole_file_gzl(
				asfd,
				sb->protocol1->datapth.buf,
				/*quick_read*/1,
				&bytes,
				/*encpassword*/NULL,
				cntr,
				/*compression*/9,
				&bfd,
				/*extrameta*/NULL,
				/*elen*/0,
				/*key_deriv*/ENCRYPTION_UNSET,
				/*salt*/0
			);
		}
		else
		{
			// If we did not do some patches, the resulting
			// file might already be gzipped. Send it as it is.
			ret=send_whole_filel(asfd,
#ifdef HAVE_WIN32
				sb->path.cmd
#endif
				sb->protocol1->datapth.buf,
				1, &bytes, cntr, &bfd, NULL, 0);
		}
	}
	bfd.close(&bfd, asfd);

	switch(ret)
	{
		case SEND_OK:
		case SEND_ERROR: // Carry on.
			return 0;
		case SEND_FATAL:
		default:
			return -1;
	}
}

#ifndef UTEST
static
#endif
int verify_file(struct asfd *asfd, struct sbuf *sb,
	int patches, const char *best, struct cntr *cntr)
{
	MD5_CTX md5;
	int b=0;
	const char *cp=NULL;
	const char *newsum=NULL;
	uint8_t in[ZCHUNK];
	uint8_t checksum[MD5_DIGEST_LENGTH];
	uint64_t cbytes=0;
	struct fzp *fzp=NULL;

	if(!sb->endfile.buf
	  || !(cp=strrchr(sb->endfile.buf, ':')))
	{
		logw(asfd, cntr,
			"%s has no md5sum!\n",
			iobuf_to_printable(&sb->protocol1->datapth));
		return 0;
	}
	cp++;
	if(!MD5_Init(&md5))
	{
		logp("MD5_Init() failed\n");
		return -1;
	}
	if(patches
	  || sb->path.cmd==CMD_ENC_FILE
	  || sb->path.cmd==CMD_ENC_METADATA
	  || sb->path.cmd==CMD_EFS_FILE
	  || sb->path.cmd==CMD_ENC_VSS
	  || sb->path.cmd==CMD_ENC_VSS_T
	  || (!patches && !dpth_protocol1_is_compressed(sb->compression, best)))
		fzp=fzp_open(best, "rb");
	else
		fzp=fzp_gzopen(best, "rb");

	if(!fzp)
	{
		logw(asfd, cntr, "could not open %s\n", best);
		return 0;
	}
	while((b=fzp_read(fzp, in, ZCHUNK))>0)
	{
		cbytes+=b;
		if(!MD5_Update(&md5, in, b))
		{
			logp("MD5_Update() failed\n");
			fzp_close(&fzp);
			return -1;
		}
	}
	if(!fzp_eof(fzp))
	{
		logw(asfd, cntr, "error while reading %s\n", best);
		fzp_close(&fzp);
		return 0;
	}
	fzp_close(&fzp);
	if(!MD5_Final(checksum, &md5))
	{
		logp("MD5_Final() failed\n");
		return -1;
	}
	newsum=bytes_to_md5str(checksum);

	if(strcmp(newsum, cp))
	{
		logp("%s %s\n", newsum, cp);
		logw(asfd, cntr, "md5sum for '%s (%s)' did not match!\n",
			iobuf_to_printable(&sb->path),
			iobuf_to_printable(&sb->protocol1->datapth));
		logp("md5sum for '%s (%s)' did not match!\n",
			iobuf_to_printable(&sb->path),
			iobuf_to_printable(&sb->protocol1->datapth));
		return 0;
	}

	// Just send the file name to the client, so that it can show cntr.
	if(asfd->write(asfd, &sb->path)) return -1;
	return 0;
}

static int process_data_dir_file(struct asfd *asfd,
	struct bu *bu, struct bu *b, const char *path,
	struct sbuf *sb, enum action act, struct sdirs *sdirs,
	struct conf **cconfs)
{
	int ret=-1;
	int patches=0;
	char *dpath=NULL;
	struct stat dstatp;
	const char *tmp=NULL;
	const char *best=NULL;
	static char *tmppath1=NULL;
	static char *tmppath2=NULL;
	struct cntr *cntr=NULL;
	if(cconfs) cntr=get_cntr(cconfs);

	if((!tmppath1 && !(tmppath1=prepend_s(bu->path, "tmp1")))
	  || (!tmppath2 && !(tmppath2=prepend_s(bu->path, "tmp2"))))
		goto end;

	best=path;
	tmp=tmppath1;
	// Now go down the list, applying any deltas.
	for(b=b->prev; b && b->next!=bu; b=b->prev)
	{
		free_w(&dpath);
		if(!(dpath=prepend_s(b->delta, sb->protocol1->datapth.buf)))
			goto end;

		if(lstat(dpath, &dstatp) || !S_ISREG(dstatp.st_mode))
			continue;

		if(!patches)
		{
			// Need to gunzip the first one.
			if(inflate_or_link_oldfile(asfd, best, tmp,
				cconfs, sb->compression))
			{
				logw(asfd, cntr,
				  "problem when inflating %s\n", best);
				ret=0;
				goto end;
			}
			best=tmp;
			if(tmp==tmppath1) tmp=tmppath2;
			else tmp=tmppath1;
		}

		if(do_patch(best, dpath, tmp,
			0 /* do not gzip the result */,
			sb->compression /* from the manifest */))
		{
			logw(asfd, cntr, "problem when patching %s with %s\n", path, b->timestamp);
			ret=0;
			goto end;
		}

		best=tmp;
		if(tmp==tmppath1) tmp=tmppath2;
		else tmp=tmppath1;
		unlink(tmp);
		patches++;
	}

	switch(act)
	{
		case ACTION_RESTORE:
			if(do_send_file(asfd, sb, patches, best, cntr))
				goto end;
			break;
		case ACTION_VERIFY:
			if(verify_file(asfd, sb, patches, best, cntr))
				goto end;
			break;
		default:
			logp("Unknown action: %d\n", act);
			goto end;
	}
	cntr_add(cntr, sb->path.cmd, 0);
	cntr_add_bytes(cntr, strtoull(sb->endfile.buf, NULL, 10));

	ret=0;
end:
	free_w(&dpath);
	if(tmppath1) unlink(tmppath1);
	if(tmppath2) unlink(tmppath2);
	free_w(&tmppath1);
	free_w(&tmppath2);
	return ret;
}

// a = length of struct bu array
// i = position to restore from
#ifndef UTEST
static
#endif
int restore_file(struct asfd *asfd, struct bu *bu,
	struct sbuf *sb, enum action act,
	struct sdirs *sdirs, struct conf **cconfs)
{
	int ret=-1;
	char *path=NULL;
	struct bu *b;
	struct bu *hlwarn=NULL;
	struct stat statp;
	struct cntr *cntr=NULL;
	if(cconfs) cntr=get_cntr(cconfs);

	// Go up the array until we find the file in the data directory.
	for(b=bu; b; b=b->next)
	{
		free_w(&path);
		if(!(path=prepend_s(b->data, sb->protocol1->datapth.buf)))
			goto end;

		if(lstat(path, &statp) || !S_ISREG(statp.st_mode))
			continue;

		if(b!=bu && (bu->flags & BU_HARDLINKED)) hlwarn=b;

		if(process_data_dir_file(asfd, bu, b,
			path, sb, act, sdirs, cconfs))
				goto end;

		// This warning must be done after everything else,
		// Because the client does not expect another cmd after
		// the warning.
		if(hlwarn) logw(asfd, cntr, "restore found %s in %s\n",
			iobuf_to_printable(&sb->path),
			hlwarn->basename);
		ret=0; // All OK.
		break;
	}

	if(!b)
	{
		logw(asfd, cntr, "restore could not find %s (%s)\n",
			iobuf_to_printable(&sb->path),
			iobuf_to_printable(&sb->protocol1->datapth));
		ret=0; // Carry on to subsequent files.
	}
end:
	free_w(&path);
	return ret;
}

int restore_sbuf_protocol1(struct asfd *asfd, struct sbuf *sb, struct bu *bu,
	enum action act, struct sdirs *sdirs, struct conf **cconfs)
{
	if((sb->protocol1->datapth.buf
		&& asfd->write(asfd, &(sb->protocol1->datapth)))
	  || asfd->write(asfd, &sb->attr))
		return -1;
	else if(sbuf_is_filedata(sb)
	  || sbuf_is_vssdata(sb))
	{
		if(!sb->protocol1->datapth.buf)
		{
			logw(asfd, get_cntr(cconfs),
				"Got filedata entry with no datapth: %s\n",
					iobuf_to_printable(&sb->path));
			return 0;
		}
		return restore_file(asfd, bu, sb, act, sdirs, cconfs);
	}
	else
	{
		if(asfd->write(asfd, &sb->path))
			return -1;
		// If it is a link, send what
		// it points to.
		else if(sbuf_is_link(sb)
		  && asfd->write(asfd, &sb->link)) return -1;
		cntr_add(get_cntr(cconfs), sb->path.cmd, 0);
	}
	return 0;
}
