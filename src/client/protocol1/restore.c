#include "../../burp.h"
#include "../../action.h"
#include "../../alloc.h"
#include "../../asfd.h"
#include "../../async.h"
#include "../../attribs.h"
#include "../../bfile.h"
#include "../../cmd.h"
#include "../../cntr.h"
#include "../../fsops.h"
#include "../../handy.h"
#include "../../log.h"
#include "../../protocol1/msg.h"
#include "../extrameta.h"
#include "../restore.h"
#include "restore.h"

static int do_restore_file_or_get_meta(struct asfd *asfd, struct BFILE *bfd,
	struct sbuf *sb, const char *fname,
	char **metadata, size_t *metalen,
	struct cntr *cntr, const char *rpath,
	const char *encryption_password)
{
	int ret=-1;
	int enccompressed=0;
	uint64_t rcvdbytes=0;
	uint64_t sentbytes=0;
	const char *encpassword=NULL;
	int key_deriv=0;

	if(sbuf_is_encrypted(sb))
	{
		encpassword=encryption_password;
		if(sb->encryption==ENCRYPTION_KEY_DERIVED)
			key_deriv=1;
	}
	enccompressed=dpth_protocol1_is_compressed(sb->compression,
		sb->protocol1->datapth.buf);

/*
	if(encpassword && !enccompressed)
		printf("encrypted and not compressed\n");
	else if(!encpassword && enccompressed)
		printf("not encrypted and compressed\n");
	else if(!encpassword && !enccompressed)
		printf("not encrypted and not compressed\n");
	else if(encpassword && enccompressed)
		printf("encrypted and compressed\n");
*/

	if(metadata)
	{
		ret=transfer_gzfile_inl(asfd,
#ifdef HAVE_WIN32
			sb,
#endif
			NULL,
			&rcvdbytes, &sentbytes, encpassword,
			enccompressed, cntr, metadata,
			key_deriv, sb->protocol1->salt);
		*metalen=sentbytes;
		// skip setting cntr, as we do not actually
		// restore until a bit later
	}
	else
	{
		ret=transfer_gzfile_inl(asfd,
#ifdef HAVE_WIN32
			sb,
#endif
			bfd,
			&rcvdbytes, &sentbytes,
			encpassword, enccompressed,
			cntr, NULL, key_deriv, sb->protocol1->salt);
#ifndef HAVE_WIN32
		if(bfd && bfd->close(bfd, asfd))
		{
			logp("error closing %s in %s\n",
				fname, __func__);
			ret=-1;
		}
		// For Windows, only set the attribs when it closes the file,
		// so that trailing vss does not get blocked after having set
		// a read-only attribute.
		if(!ret) attribs_set(asfd, rpath,
			&sb->statp, sb->winattr, cntr);
#endif
	}
	if(ret)
	{
		char msg[256]="";
		snprintf(msg, sizeof(msg),
			"Could not transfer file in: %s", rpath);
		return restore_interrupt(asfd, sb, msg, cntr);
	}
	return 0;
}

static int restore_file_or_get_meta(struct asfd *asfd, struct BFILE *bfd,
	struct sbuf *sb, const char *fname, enum action act,
	char **metadata, size_t *metalen, enum vss_restore vss_restore,
	struct cntr *cntr, const char *encyption_password)
{
	int ret=0;
	char *rpath=NULL;

	if(act==ACTION_VERIFY)
	{
		cntr_add(cntr, sb->path.cmd, 1);
		goto end;
	}

	if(build_path(fname, "", &rpath, NULL))
	{
		char msg[256]="";
		// failed - do a warning
		snprintf(msg, sizeof(msg), "build path failed: %s", fname);
		if(restore_interrupt(asfd, sb, msg, cntr))
			ret=-1;
		goto end;
	}

#ifndef HAVE_WIN32
	// We always want to open the file if it is on Windows. Otherwise,
	// only open it if we are not doing metadata.
	if(!metadata)
	{
#endif
		switch(open_for_restore(asfd,
			bfd, rpath, sb, vss_restore, cntr))
		{
			case OFR_OK: break;
			case OFR_CONTINUE: goto end;
			default: ret=-1; goto end;
		}
#ifndef HAVE_WIN32
	}
#endif

	if(!(ret=do_restore_file_or_get_meta(asfd, bfd, sb, fname,
		metadata, metalen, cntr, rpath, encyption_password)))
	{
		// Only add to counters if we are not doing metadata. The
		// actual metadata restore comes a bit later.
		if(!metadata)
			cntr_add(cntr, sb->path.cmd, 1);
	}
end:
	free_w(&rpath);
	if(ret) logp("restore_file error\n");
	return ret;
}

static int restore_metadata(struct asfd *asfd,
	struct BFILE *bfd, struct sbuf *sb,
	const char *fname, enum action act,
	enum vss_restore vss_restore,
	struct cntr *cntr, const char *encryption_password)
{
	int ret=-1;
	size_t metalen=0;
	char *metadata=NULL;

	// If it is directory metadata, try to make sure the directory
	// exists. Pass in NULL as the cntr, so no counting is done.
	// The actual directory entry will be coming after the metadata,
	// annoyingly. This is because of the way that the server is queuing
	// up directories to send after file data, so that the stat info on
	// them gets set correctly.
	if(act==ACTION_VERIFY)
	{
		cntr_add(cntr, sb->path.cmd, 1);
		ret=0;
		goto end;
	}

	// Create the directory, but do not add to the counts.
	if(S_ISDIR(sb->statp.st_mode)
	  && restore_dir(asfd, sb, fname, act, /*cntr*/NULL))
		goto end;

	// Read in the metadata...
	if(restore_file_or_get_meta(asfd, bfd, sb, fname, act,
		&metadata, &metalen, vss_restore, cntr, encryption_password))
			goto end;
	if(metadata)
	{
		if(!set_extrameta(asfd,
#ifdef HAVE_WIN32
			bfd,
#endif
			fname,
			metadata, metalen, cntr))
		{
#ifndef HAVE_WIN32
			// Set file times again, since we just diddled with the
			// file. Do not set all attributes, as it will wipe
			// out any security attributes (eg getcap /usr/bin/ping)
			if(attribs_set_file_times(asfd, fname,
				&sb->statp, cntr))
					return -1;
			cntr_add(cntr, sb->path.cmd, 1);
#endif
		}
		// Carry on if we could not set_extrameta.
	}
	ret=0;
end:
	free_w(&metadata);
	return ret;
}

int restore_switch_protocol1(struct asfd *asfd, struct sbuf *sb,
	const char *fullpath, enum action act,
	struct BFILE *bfd, enum vss_restore vss_restore, struct cntr *cntr,
	const char *encryption_password)
{
	switch(sb->path.cmd)
	{
		case CMD_FILE:
		case CMD_VSS_T:
		case CMD_ENC_FILE:
		case CMD_ENC_VSS_T:
		case CMD_EFS_FILE:
			if(!sb->protocol1->datapth.buf)
			{
				char msg[256];
				snprintf(msg, sizeof(msg),
				  "datapth not supplied for %s in %s\n",
					iobuf_to_printable(&sb->path),
					__func__);
				log_and_send(asfd, msg);
				return -1;
			}
			return restore_file_or_get_meta(asfd, bfd, sb,
				fullpath, act,
				NULL, NULL, vss_restore, cntr,
				encryption_password);
		case CMD_METADATA:
		case CMD_VSS:
		case CMD_ENC_METADATA:
		case CMD_ENC_VSS:
			return restore_metadata(asfd, bfd, sb,
				fullpath, act,
				vss_restore, cntr, encryption_password);
		default:
			// Other cases (dir/links/etc) are handled in the
			// calling function.
			logp("unknown cmd: %s\n",
				iobuf_to_printable(&sb->path));
			return -1;
	}
}
