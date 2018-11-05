#include "../../burp.h"
#include "../../alloc.h"
#include "../../asfd.h"
#include "../../async.h"
#include "../../attribs.h"
#include "../../bfile.h"
#include "../../cmd.h"
#include "../../cntr.h"
#include "../../fsops.h"
#include "../../log.h"
#include "../../sbuf.h"
#include "../extrameta.h"
#include "../restore.h"
#include "restore.h"

int write_protocol2_data(struct asfd *asfd,
	struct BFILE *bfd, struct blk *blk, int vss_restore)
{
	if(bfd->mode==BF_CLOSED)
		logp("Got data without an open file\n");
	else
	{
		int w;
		if((w=bfd->write(bfd, blk->data, blk->length))<=0)
		{
			logp("%s(): error when appending %d: %d\n",
					__func__, blk->length, w);
			asfd->write_str(asfd, CMD_ERROR, "write failed");
			return -1;
		}
	}
	return 0;
}

static int start_restore_file(struct asfd *asfd,
	struct BFILE *bfd,
	struct sbuf *sb,
	const char *fname,
	enum action act,
	int vss_restore,
	struct cntr *cntr)
{
	int ret=-1;
	char *rpath=NULL;

	if(act==ACTION_VERIFY)
	{
		cntr_add(cntr, sb->path.cmd, 1);
		goto end;
	}

	if(build_path(fname, "", &rpath, NULL))
	{
		char msg[256]="";
		// Failed - do a warning.
		snprintf(msg, sizeof(msg), "build path failed: %s", fname);
		if(restore_interrupt(asfd, sb, msg, cntr, PROTO_2))
			goto error;
		goto end; // Try to carry on with other files.
	}

	switch(open_for_restore(asfd, bfd, rpath, sb, vss_restore, cntr,
		PROTO_2))
	{
		case OFR_OK: break;
		case OFR_CONTINUE: goto end;
		default: goto error;
	}

	cntr_add(cntr, sb->path.cmd, 1);

end:
	ret=0;
error:
	free_w(&rpath);
	return ret;
}

static int get_meta(
	struct asfd *asfd,
	struct cntr *cntr,
	char **metadata,
	size_t *metalen)
{
	int ret=-1;
	struct iobuf *rbuf=asfd->rbuf;

	while(1)
	{
		iobuf_free_content(rbuf);
		if(asfd->read(asfd))
			goto end;

		switch(rbuf->cmd)
		{
			case CMD_DATA:
				if(!(*metadata=(char *)realloc_w(*metadata,
					(*metalen)+rbuf->len, __func__)))
						goto end;
				memcpy((*metadata)+(*metalen),
					rbuf->buf, rbuf->len);
				*metalen+=rbuf->len;
				break;
			case CMD_END_FILE:
				ret=0;
				goto end;
			case CMD_MESSAGE:
			case CMD_WARNING:
				log_recvd(rbuf, cntr, 0);
				break;
			default:
				iobuf_log_unexpected(rbuf, __func__);
				goto end;
		}
	}

end:
	iobuf_free_content(rbuf);
	return ret;
}

static int restore_metadata(
	struct asfd *asfd,
	struct sbuf *sb,
	const char *fname,
	enum action act,
	struct cntr *cntr)
{
	// If it is directory metadata, try to make sure the directory
	// exists. Pass in NULL as the cntr, so no counting is done.
	// The actual directory entry will be coming after the metadata,
	// annoyingly. This is because of the way that the server is queuing
	// up directories to send after file data, so that the stat info on
	// them gets set correctly.
	if(act==ACTION_RESTORE)
	{
		size_t metalen=0;
		char *metadata=NULL;
		if(S_ISDIR(sb->statp.st_mode)
		  && restore_dir(asfd, sb, fname, act, /*cntr*/NULL, PROTO_2))
			return -1;

		// Read in the metadata...
		if(get_meta(asfd, cntr, &metadata, &metalen))
			return -1;
		if(metadata)
		{
			if(set_extrameta(asfd,
#ifdef HAVE_WIN32
				NULL,
#endif
				fname,
				metadata, metalen, cntr))
			{
				free_w(&metadata);
				// carry on if we could not do it
				return 0;
			}
			free_w(&metadata);
#ifndef HAVE_WIN32
			// Set file times again, since we just diddled with the
			// file. Do not set all attributes, as it will wipe
			// out any security attributes (eg getcap /usr/bin/ping)
			if(attribs_set_file_times(asfd, fname,
				&sb->statp, cntr))
					return -1;
#endif
			cntr_add(cntr, sb->path.cmd, 1);
		}
	}
	else
		cntr_add(cntr, sb->path.cmd, 1);
	return 0;
}

int restore_switch_protocol2(struct asfd *asfd, struct sbuf *sb,
	const char *fullpath, enum action act,
	struct BFILE *bfd, int vss_restore, struct cntr *cntr)
{
	switch(sb->path.cmd)
	{
		case CMD_FILE:
			// Have it a separate statement to the
			// encrypted version so that encrypted and not
			// encrypted files can be restored at the
			// same time.
			if(start_restore_file(asfd,
				bfd, sb, fullpath, act,
				vss_restore, cntr))
			{
				logp("restore_file error\n");
				goto error;
			}
			break;
/* FIX THIS: Encryption currently not working in protocol2
		case CMD_ENC_FILE:
			if(start_restore_file(asfd,
				bfd, sb, fullpath, act,
				vss_restore, confs))
			{
				logp("restore_file error\n");
				goto error;
			}
			break;
*/
		case CMD_METADATA:
			if(restore_metadata(asfd,
				sb, fullpath, act, cntr))
					goto error;
			break;
/* FIX THIS: Encryption and EFS not supported yet.
		case CMD_ENC_METADATA:
			if(restore_metadata(
				bfd, sb, fullpath, act, confs))
					goto error;
			break;
		case CMD_EFS_FILE:
			if(start_restore_file(asfd,
				bfd, sb,
				fullpath, act,
				vss_restore, confs))
			{
				logp("restore_file error\n");
				goto error;
			}
			break;
*/
		default:
			logp("unknown cmd: %c\n", sb->path.cmd);
			goto error;
	}
	return 0;
error:
	return -1;
}
