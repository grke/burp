#include "include.h"

static int open_for_restore(struct asfd *asfd, BFILE *bfd, FILE **fp,
	const char *path, struct sbuf *sb, int vss_restore, struct conf *conf)
{
#ifdef HAVE_WIN32
	if(bfd->mode!=BF_CLOSED)
	{
		if(bfd->path && !strcmp(bfd->path, path))
		{
			// Already open after restoring the VSS data.
			// Time now for the actual file data.
			return 0;
		}
		else
		{
			if(bclose(bfd, asfd))
			{
				logp("error closing %s in %s()\n",
					path, __func__);
				return -1;
			}
		}
	}
	binit(bfd, sb->winattr, conf);
	if(vss_restore)
		set_win32_backup(bfd);
	else
		bfd->use_backup_api=0;
	if(bopen(bfd, asfd, path, O_WRONLY | O_CREAT | O_TRUNC | O_BINARY,
		S_IRUSR | S_IWUSR))
	{
		berrno be;
		berrno_init(&be);
		char msg[256]="";
		snprintf(msg, sizeof(msg),
			"Could not open for writing %s: %s",
				path, berrno_bstrerror(&be, errno));
		if(restore_interrupt(asfd, sb, msg, conf))
			return -1;
	}
#else
	if(!(*fp=open_file(path, "wb")))
	{
		char msg[256]="";
		snprintf(msg, sizeof(msg),
			"Could not open for writing %s: %s",
				path, strerror(errno));
		if(restore_interrupt(asfd, sb, msg, conf))
			return -1;
	}
#endif
	// Add attributes to bfd so that they can be set when it is closed.
	bfd->winattr=sb->winattr;
	memcpy(&bfd->statp, &sb->statp, sizeof(struct stat));
	return 0;
}

static int restore_file_or_get_meta(struct asfd *asfd, BFILE *bfd,
	struct sbuf *sb, const char *fname, enum action act,
	const char *encpassword, char **metadata, size_t *metalen,
	int vss_restore, struct conf *conf)
{
	int ret=0;
	char *rpath=NULL;
	FILE *fp=NULL;

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
		goto end;
	}

#ifndef HAVE_WIN32
	// We always want to open the file if it is on Windows. Otherwise,
	// only open it if we are not doing metadata.
	if(!metadata)
	{
#endif
		if(open_for_restore(asfd, bfd, &fp,
			rpath, sb, vss_restore, conf))
		{
			ret=-1;
			goto end;
		}
#ifndef HAVE_WIN32
	}
#endif

	if(!ret)
	{
		int enccompressed=0;
		unsigned long long rcvdbytes=0;
		unsigned long long sentbytes=0;

		enccompressed=dpthl_is_compressed(sb->compression, sb->burp1->datapth.buf);
/*
		printf("%s \n", fname);
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
			ret=transfer_gzfile_inl(asfd, sb, fname, NULL, NULL,
				&rcvdbytes, &sentbytes,
				encpassword, enccompressed,
				conf->cntr, metadata);
			*metalen=sentbytes;
			// skip setting cntr, as we do not actually
			// restore until a bit later
			goto end;
		}
		else
		{
			int c=0;
#ifdef HAVE_WIN32
			ret=transfer_gzfile_inl(asfd, sb, fname, bfd, NULL,
				&rcvdbytes, &sentbytes,
				encpassword, enccompressed, conf->cntr, NULL);
			//c=bclose(bfd);
#else
			ret=transfer_gzfile_inl(asfd, sb, fname, NULL, fp,
				&rcvdbytes, &sentbytes,
				encpassword, enccompressed, conf->cntr, NULL);
			c=close_fp(&fp);
#endif
			if(c)
			{
				logp("error closing %s in restore_file_or_get_meta\n", fname);
				ret=-1;
			}
			if(!ret) attribs_set(asfd, rpath,
				&(sb->statp), sb->winattr, conf);
		}
		if(ret)
		{
			char msg[256]="";
			snprintf(msg, sizeof(msg),
				"Could not transfer file in: %s",
					rpath);
			if(restore_interrupt(asfd, sb, msg, conf))
				ret=-1;
			goto end;
		}
	}
	if(!ret) cntr_add(conf->cntr, sb->path.cmd, 1);
end:
	if(rpath) free(rpath);
	return ret;
}

static int restore_metadata(struct asfd *asfd, BFILE *bfd, struct sbuf *sb,
	const char *fname, enum action act, const char *encpassword,
	int vss_restore, struct conf *conf)
{
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
		cntr_add(conf->cntr, sb->path.cmd, 1);
		return 0;
	}

	if(S_ISDIR(sb->statp.st_mode)
	  && restore_dir(asfd, sb, fname, act, NULL))
		return -1;

	// Read in the metadata...
	if(restore_file_or_get_meta(asfd, bfd, sb, fname, act, encpassword,
		&metadata, &metalen, vss_restore, conf))
			return -1;
	if(metadata)
	{
		
		if(set_extrameta(asfd,
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
		// Set attributes again, since we just diddled with the file.
		attribs_set(asfd, fname, &(sb->statp), sb->winattr, conf);
#endif
		cntr_add(conf->cntr, sb->path.cmd, 1);
	}
	return 0;
}

int restore_switch_burp1(struct asfd *asfd, struct sbuf *sb,
	const char *fullpath, enum action act,
	BFILE *bfd, int vss_restore, struct conf *conf)
{
	switch(sb->path.cmd)
	{
		case CMD_FILE:
		case CMD_VSS_T:
			// Have it a separate statement to the
			// encrypted version so that encrypted and not
			// encrypted files can be restored at the
			// same time.
			if(restore_file_or_get_meta(asfd, bfd, sb,
				fullpath, act,
				NULL, NULL, NULL,
				vss_restore, conf))
			{
				logp("restore_file error\n");
				goto error;
			}
			break;
		case CMD_ENC_FILE:
		case CMD_ENC_VSS_T:
			if(restore_file_or_get_meta(asfd, bfd, sb,
				fullpath, act,
				conf->encryption_password,
				NULL, NULL, vss_restore, conf))
			{
				logp("restore_file error\n");
				goto error;
			}
			break;
		case CMD_METADATA:
		case CMD_VSS:
			if(restore_metadata(asfd, bfd, sb, fullpath,
				act, NULL, vss_restore, conf))
					goto error;
			break;
		case CMD_ENC_METADATA:
		case CMD_ENC_VSS:
			if(restore_metadata(asfd, bfd, sb, fullpath,
				act, conf->encryption_password,
				vss_restore, conf))
					goto error;
			break;
		case CMD_EFS_FILE:
			if(restore_file_or_get_meta(asfd, bfd, sb,
				fullpath, act,
				NULL, NULL, NULL, vss_restore, conf))
			{
				logp("restore_file error\n");
				goto error;
			}
			break;
		default:
			// Other cases (dir/links/etc) are handled in the
			// calling function.
			logp("unknown cmd: %c\n", sb->path.cmd);
			goto error;
	}
	return 0;
error:
	return -1;
}
