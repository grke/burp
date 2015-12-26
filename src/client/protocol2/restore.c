#include "../../burp.h"
#include "../../alloc.h"
#include "../../asfd.h"
#include "../../async.h"
#include "../../bfile.h"
#include "../../cmd.h"
#include "../../cntr.h"
#include "../../fsops.h"
#include "../../log.h"
#include "../../sbuf.h"
#include "../restore.h"

static int start_restore_file(struct asfd *asfd,
	BFILE *bfd,
	struct sbuf *sb,
	const char *fname,
	enum action act,
	const char *encpassword,
	char **metadata,
	size_t *metalen,
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

/*
static int restore_metadata(
#ifdef HAVE_WIN32
	BFILE *bfd,
#endif
	struct sbuf *sb,
	const char *fname,
	enum action act,
	const char *encpassword,
	int vss_restore,
	struct conf **confs)
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
		  && restore_dir(asfd, sb, fname, act, confs))
			return -1;

		// Read in the metadata...
		if(restore_file_or_get_meta(bfd, sb, fname, act, encpassword,
			&metadata, &metalen, vss_restore, confs))
				return -1;
		if(metadata)
		{
			if(set_extrameta(bfd, fname, sb->path.cmd,
				&(sb->statp), metadata, metalen, confs))
			{
				free_w(&metadata);
				// carry on if we could not do it
				return 0;
			}
			free_w(&metadata);
#ifndef HAVE_WIN32
			// set attributes again, since we just diddled with
			// the file
			attribs_set(fname, &(sb->statp), sb->winattr, confs);
#endif
			cntr_add(get_cntr(confs), sb->path.cmd, 1);
		}
	}
	else cntr_add(get_cntr(confs), sb->cmd, 1);
	return 0;
}
*/

int restore_switch_protocol2(struct asfd *asfd, struct sbuf *sb,
	const char *fullpath, enum action act,
	BFILE *bfd, int vss_restore, struct cntr *cntr)
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
				NULL, NULL, NULL,
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
				get_string(confs[OPT_ENCRYPTION_PASSWORD]),
				NULL, NULL, vss_restore, confs))
			{
				logp("restore_file error\n");
				goto error;
			}
			break;
*/
/* FIX THIS: Metadata and EFS not supported yet.
		case CMD_METADATA:
			if(restore_metadata(
				bfd, sb, fullpath, act,
				NULL, vss_restore, confs))
					goto error;
			break;
		case CMD_ENC_METADATA:
			if(restore_metadata(
				bfd, sb, fullpath, act,
				get_string(confs[OPT_ENCRYPTION_PASSWORD]),
				vss_restore, confs))
					goto error;
			break;
		case CMD_EFS_FILE:
			if(start_restore_file(asfd,
				bfd, sb,
				fullpath, act,
				NULL,
				NULL, NULL, vss_restore, confs))
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
