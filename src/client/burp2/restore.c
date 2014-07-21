#include "include.h"

static int start_restore_file(struct asfd *asfd,
	BFILE *bfd,
	struct sbuf *sb,
	const char *fname,
	enum action act,
	const char *encpassword,
	char **metadata,
	size_t *metalen,
	int vss_restore,
	struct conf *conf)
{
	int ret=-1;
	char *rpath=NULL;

	if(act==ACTION_VERIFY)
	{
		cntr_add(conf->cntr, sb->path.cmd, 1);
		return 0;
	}

	if(build_path(fname, "", &rpath, NULL))
	{
		char msg[256]="";
		// failed - do a warning
		snprintf(msg, sizeof(msg), "build path failed: %s", fname);
		if(restore_interrupt(asfd, sb, msg, conf))
			ret=-1;
		ret=0; // Try to carry on with other files.
		goto end;
	}

	if(open_for_restore(asfd, bfd, rpath, sb, vss_restore, conf))
		goto end;

	cntr_add(conf->cntr, sb->path.cmd, 1);

	ret=0;
end:
	if(rpath) free(rpath);
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
	struct conf *conf)
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
		  && restore_dir(asfd, sb, fname, act, NULL))
			return -1;

		// Read in the metadata...
		if(restore_file_or_get_meta(
#ifdef HAVE_WIN32
			bfd,
#endif
			sb, fname, act, encpassword,
			&metadata, &metalen, vss_restore, conf))
				return -1;
		if(metadata)
		{
			
			if(set_extrameta(
#ifdef HAVE_WIN32
				bfd,
#endif
				fname, sb->path.cmd,
				&(sb->statp), metadata, metalen, conf))
			{
				free(metadata);
				// carry on if we could not do it
				return 0;
			}
			free(metadata);
#ifndef HAVE_WIN32
			// set attributes again, since we just diddled with
			// the file
			attribs_set(fname, &(sb->statp), sb->winattr, conf);
#endif
			cntr_add(conf->cntr, sb->path.cmd, 1);
		}
	}
	else cntr_add(conf->cntr, sb->cmd, 1);
	return 0;
}
*/

int restore_switch_burp2(struct asfd *asfd, struct sbuf *sb,
	const char *fullpath, enum action act,
	BFILE *bfd, int vss_restore, struct conf *conf)
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
				vss_restore, conf))
			{
				logp("restore_file error\n");
				goto error;
			}
			break;
/* FIX THIS: Encryption currently not working in burp2
		case CMD_ENC_FILE:
			if(start_restore_file(asfd,
				bfd, sb, fullpath, act,
				conf->encryption_password,
				NULL, NULL, vss_restore, conf))
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
				NULL, vss_restore, conf))
					goto error;
			break;
		case CMD_ENC_METADATA:
			if(restore_metadata(
				bfd, sb, fullpath, act,
				conf->encryption_password,
				vss_restore, conf))
					goto error;
			break;
		case CMD_EFS_FILE:
			if(start_restore_file(asfd,
				bfd, sb,
				fullpath, act,
				NULL,
				NULL, NULL, vss_restore, conf))
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
