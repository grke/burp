#include "include.h"

static int restore_interrupt(struct sbufl *sb, const char *msg, struct config *conf)
{
	int ret=0;
	int quit=0;
	struct cntr *cntr=conf->cntr;
	static struct iobuf *rbuf=NULL;

	if(!cntr) return 0;

	do_filecounter(cntr, CMD_WARNING, 1);
	logp("WARNING: %s\n", msg);
	if(async_write_str(CMD_WARNING, msg)) return -1;

	// If it is file data, get the server
	// to interrupt the flow and move on.
	if((sb->cmd!=CMD_FILE
	   && sb->cmd!=CMD_ENC_FILE
	   && sb->cmd!=CMD_EFS_FILE
	   && sb->cmd!=CMD_VSS
	   && sb->cmd!=CMD_ENC_VSS
	   && sb->cmd!=CMD_VSS_T
	   && sb->cmd!=CMD_ENC_VSS_T)
	 || !(sb->datapth))
		return 0;

	if(!rbuf && !(rbuf=iobuf_alloc()))
		return -1;

	if(async_write_str(CMD_INTERRUPT, sb->datapth))
	{
		ret=-1;
		quit++;
	}

	// Read to the end file marker.
	while(!quit)
	{
		iobuf_free_content(rbuf);
		if(async_read(rbuf))
		{
			ret=-1; quit++;
		}
		if(!ret && rbuf->len)
		{
			if(rbuf->cmd==CMD_APPEND)
			{
				continue;
			}
			else if(rbuf->cmd==CMD_END_FILE)
			{
				break;
			}
			else
			{
				iobuf_log_unexpected(rbuf, __FUNCTION__);
				ret=-1; quit++;
			}
		}
	}
	iobuf_free_content(rbuf);
	return ret;
}

static int make_link(const char *fname, const char *lnk, char cmd, const char *restoreprefix, struct config *conf)
{
	int ret=-1;

#ifdef HAVE_WIN32
	logw(conf->cntr, "windows seems not to support hardlinks or symlinks\n");
#else
	unlink(fname);
	if(cmd==CMD_HARD_LINK)
	{
		char *flnk=NULL;
		if(!(flnk=prepend_s(restoreprefix, lnk)))
		{
			log_out_of_memory(__FUNCTION__);
			return -1;
		}
		//printf("%s -> %s\n", fname, flnk);
		ret=link(flnk, fname);
		free(flnk);
	}
	else if(cmd==CMD_SOFT_LINK)
	{
		//printf("%s -> %s\n", fname, lnk);
		ret=symlink(lnk, fname);
	}
	else
	{
		logp("unexpected link command: %c\n", cmd);
		ret=-1;
	}
#endif

	if(ret) logp("could not %slink %s -> %s: %s\n",
		cmd==CMD_HARD_LINK?"hard":"sym",
		fname, lnk, strerror(errno));

	return ret;
}

static int open_for_restore(BFILE *bfd, FILE **fp, const char *path, struct sbufl *sb, int vss_restore, struct config *conf)
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
			if(bclose(bfd))
			{
				logp("error closing %s in %s()\n",
					path, __FUNCTION__);
				return -1;
			}
		}
	}
	binit(bfd, sb->winattr, conf);
	if(vss_restore)
		set_win32_backup(bfd);
	else
		bfd->use_backup_api=0;
	if(bopen(bfd, path, O_WRONLY | O_CREAT | O_TRUNC | O_BINARY,
		S_IRUSR | S_IWUSR)<=0)
	{
		berrno be;
		char msg[256]="";
		snprintf(msg, sizeof(msg),
			"Could not open for writing %s: %s",
				path, be.bstrerror(errno));
		if(restore_interrupt(sb, msg, conf))
			return -1;
	}
#else
	if(!(*fp=open_file(path, "wb")))
	{
		char msg[256]="";
		snprintf(msg, sizeof(msg),
			"Could not open for writing %s: %s",
				path, strerror(errno));
		if(restore_interrupt(sb, msg, conf))
			return -1;
	}
#endif
	// Add attributes to bfd so that they can be set when it is closed.
	bfd->winattr=sb->winattr;
	memcpy(&bfd->statp, &sb->statp, sizeof(struct stat));
	return 0;
}

static int restore_file_or_get_meta(BFILE *bfd, struct sbufl *sb, const char *fname, enum action act, const char *encpassword, char **metadata, size_t *metalen, int vss_restore, struct config *conf)
{
	int ret=0;
	char *rpath=NULL;
	FILE *fp=NULL;

	if(act==ACTION_VERIFY)
	{
		do_filecounter(conf->cntr, sb->cmd, 1);
		return 0;
	}

	if(build_path(fname, "", &rpath, NULL))
	{
		char msg[256]="";
		// failed - do a warning
		snprintf(msg, sizeof(msg), "build path failed: %s", fname);
		if(restore_interrupt(sb, msg, conf))
			ret=-1;
		goto end;
	}

#ifndef HAVE_WIN32
	// We always want to open the file if it is on Windows. Otherwise,
	// only open it if we are not doing metadata.
	if(!metadata)
	{
#endif
		if(open_for_restore(bfd, &fp,
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

		enccompressed=dpth_is_compressed(sb->compression, sb->datapth);
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
			ret=transfer_gzfile_in(sb, fname, NULL, NULL,
				&rcvdbytes, &sentbytes,
				encpassword, enccompressed,
				conf->cntr, metadata);
			*metalen=sentbytes;
			// skip setting the file counter, as we do not actually
			// restore until a bit later
			goto end;
		}
		else
		{
			int c=0;
#ifdef HAVE_WIN32
			ret=transfer_gzfile_in(sb, fname, bfd, NULL,
				&rcvdbytes, &sentbytes,
				encpassword, enccompressed, conf->cntr, NULL);
			//c=bclose(bfd);
#else
			ret=transfer_gzfile_in(sb, fname, NULL, fp,
				&rcvdbytes, &sentbytes,
				encpassword, enccompressed, conf->cntr, NULL);
			c=close_fp(&fp);
#endif
			if(c)
			{
				logp("error closing %s in restore_file_or_get_meta\n", fname);
				ret=-1;
			}
			if(!ret) set_attributes(rpath, sb->cmd,
				&(sb->statp), sb->winattr, conf->cntr);
		}
		if(ret)
		{
			char msg[256]="";
			snprintf(msg, sizeof(msg),
				"Could not transfer file in: %s",
					rpath);
			if(restore_interrupt(sb, msg, conf))
				ret=-1;
			goto end;
		}
	}
	if(!ret) do_filecounter(conf->cntr, sb->cmd, 1);
end:
	if(rpath) free(rpath);
	return ret;
}

static int restore_special(struct sbufl *sb, const char *fname, enum action act, struct config *conf)
{
	int ret=0;
	char *rpath=NULL;
#ifdef HAVE_WIN32
	logw(conf->cntr, "Cannot restore special files to Windows: %s\n", fname);
	goto end;
#else
	struct stat statp=sb->statp;

	if(act==ACTION_VERIFY)
	{
		do_filecounter(conf->cntr, CMD_SPECIAL, 1);
		return 0;
	}

	if(build_path(fname, "", &rpath, NULL))
	{
		char msg[256]="";
		// failed - do a warning
		snprintf(msg, sizeof(msg), "build path failed: %s", fname);
		if(restore_interrupt(sb, msg, conf))
			ret=-1;
		goto end;
	}
	if(S_ISFIFO(statp.st_mode))
	{
		if(mkfifo(rpath, statp.st_mode) && errno!=EEXIST)
		{
			char msg[256]="";
			snprintf(msg, sizeof(msg),
				"Cannot make fifo: %s\n", strerror(errno));
			logw(conf->cntr, "%s", msg);
		}
		else
		{
			set_attributes(rpath, CMD_SPECIAL, &statp, sb->winattr, conf->cntr);
			do_filecounter(conf->cntr, CMD_SPECIAL, 1);
		}
/*
	}
	else if(S_ISSOCK(statp.st_mode)) {
		char msg[256]="";
		snprintf(msg, sizeof(msg),
			"Skipping restore of socket: %s\n", fname);
		logw(conf->cntr, "%s", msg);
*/
#ifdef S_IFDOOR     // Solaris high speed RPC mechanism
	} else if (S_ISDOOR(statp.st_mode)) {
		char msg[256]="";
		snprintf(msg, sizeof(msg),
			"Skipping restore of door file: %s\n", fname);
		logw(conf->cntr, "%s", msg);
#endif
#ifdef S_IFPORT     // Solaris event port for handling AIO
	} else if (S_ISPORT(statp.st_mode)) {
		char msg[256]="";
		snprintf(msg, sizeof(msg),
			"Skipping restore of event port file: %s\n", fname);
		logw(conf->cntr, "%s", msg);
#endif
	} else {
            if(mknod(fname, statp.st_mode, statp.st_rdev) && errno!=EEXIST)
	    {
		char msg[256]="";
		snprintf(msg, sizeof(msg),
			"Cannot make node: %s\n", strerror(errno));
		logw(conf->cntr, "%s", msg);
            }
	    else
	    {
		set_attributes(rpath, CMD_SPECIAL, &statp, sb->winattr, conf->cntr);
		do_filecounter(conf->cntr, CMD_SPECIAL, 1);
	    }
         }
#endif
end:
	if(rpath) free(rpath);
	return ret;
}

static int restore_dir(struct sbufl *sb, const char *dname, enum action act, struct config *conf)
{
	int ret=0;
	char *rpath=NULL;
	if(act==ACTION_RESTORE)
	{
		if(build_path(dname, "", &rpath, NULL))
		{
			char msg[256]="";
			// failed - do a warning
			snprintf(msg, sizeof(msg),
				"build path failed: %s", dname);
			if(restore_interrupt(sb, msg, conf))
				ret=-1;
			goto end;
		}
		else if(!is_dir_lstat(rpath))
		{
			if(mkdir(rpath, 0777))
			{
				char msg[256]="";
				snprintf(msg, sizeof(msg), "mkdir error: %s",
					strerror(errno));
				// failed - do a warning
				if(restore_interrupt(sb, msg, conf))
					ret=-1;
				goto end;
			}
		}
		else
		{
			set_attributes(rpath,
				sb->cmd, &(sb->statp), sb->winattr, conf->cntr);
		}
		if(!ret) do_filecounter(conf->cntr, sb->cmd, 1);
	}
	else do_filecounter(conf->cntr, sb->cmd, 1);
end:
	if(rpath) free(rpath);
	return ret;
}

static int restore_link(struct sbufl *sb, const char *fname, const char *restoreprefix, enum action act, struct config *conf)
{
	int ret=0;

	if(act==ACTION_RESTORE)
	{
		char *rpath=NULL;
		if(build_path(fname, "", &rpath, NULL))
		{
			char msg[256]="";
			// failed - do a warning
			snprintf(msg, sizeof(msg), "build path failed: %s",
				fname);
			if(restore_interrupt(sb, msg, conf))
				ret=-1;
			goto end;
		}
		else if(make_link(fname, sb->linkto, sb->cmd,
			restoreprefix, conf))
		{
			// failed - do a warning
			if(restore_interrupt(sb, "could not create link", conf))
				ret=-1;
			goto end;
		}
		else if(!ret)
		{
			set_attributes(fname,
				sb->cmd, &(sb->statp), sb->winattr, conf->cntr);
			do_filecounter(conf->cntr, sb->cmd, 1);
		}
		if(rpath) free(rpath);
	}
	else do_filecounter(conf->cntr, sb->cmd, 1);
end:
	return ret;
}

static int restore_metadata(BFILE *bfd, struct sbufl *sb, const char *fname, enum action act, const char *encpassword, int vss_restore, struct config *conf)
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
		  && restore_dir(sb, fname, act, NULL))
			return -1;

		// Read in the metadata...
		if(restore_file_or_get_meta(bfd, sb, fname, act, encpassword,
			&metadata, &metalen, vss_restore, conf))
				return -1;
		if(metadata)
		{
			
			if(set_extrameta(
#ifdef HAVE_WIN32
				bfd,
#endif
				fname, sb->cmd,
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
			set_attributes(fname, sb->cmd,
				&(sb->statp), sb->winattr, conf->cntr);
#endif
			do_filecounter(conf->cntr, sb->cmd, 1);
		}
	}
	else do_filecounter(conf->cntr, sb->cmd, 1);
	return 0;
}

static void strip_invalid_characters(char **path)
{
#ifdef HAVE_WIN32
      char *ch = *path;
      if (ch[0] != 0 && ch[1] != 0) {
         ch += 2;
         while (*ch) {
            switch (*ch) {
            case ':':
            case '<':
            case '>':
            case '*':
            case '?':
            case '|':
               *ch = '_';
                break;
            }
            ch++;
         }
      }
#endif
}

static const char *act_str(enum action act)
{
	static const char *ret=NULL;
	if(act==ACTION_RESTORE) ret="restore";
	else ret="verify";
	return ret;
}

/* Return 1 for ok, -1 for error, 0 for too many components stripped. */
static int strip_path_components(struct sbufl *sb, char **path, struct config *conf)
{
	int s=0;
	char *tmp=NULL;
	char *cp=*path;
	char *dp=NULL;
	for(s=0; cp && *cp && s<conf->strip; s++)
	{
		if(!(dp=strchr(cp, '/')))
		{
			char msg[256]="";
			snprintf(msg, sizeof(msg),
				"Stripped too many components: %s", *path);
			if(restore_interrupt(sb, msg, conf))
				return -1;
			return 0;
		}
		cp=dp+1;
	}
	if(!cp)
	{
		char msg[256]="";
		snprintf(msg, sizeof(msg),
			"Stripped too many components: %s", *path);
		if(restore_interrupt(sb, msg, conf))
			return -1;
		return 0;
	}
	if(!(tmp=strdup(cp)))
	{
		log_and_send_oom(__FUNCTION__);
		return -1;
	}
	free(*path);
	*path=tmp;
	return 1;
}

static int overwrite_ok(struct sbufl *sb, struct config *conf, BFILE *bfd, const char *fullpath)
{
	struct stat checkstat;

	// User specified overwrite is OK.
#ifdef HAVE_WIN32
	if(conf->overwrite) return 1;
#else
	// User specified overwrite is OK,
	// UNLESS we're trying to overwrite the file with the trailing VSS data
	if(conf->overwrite)
		return (sb->cmd!=CMD_VSS_T
			&& sb->cmd!=CMD_ENC_VSS_T);
#endif

	if(!S_ISDIR(sb->statp.st_mode)
	  && sb->cmd!=CMD_METADATA
	  && sb->cmd!=CMD_ENC_METADATA
	  && sb->cmd!=CMD_VSS
	  && sb->cmd!=CMD_ENC_VSS)
	{
#ifdef HAVE_WIN32
		// If Windows previously got some VSS data, it needs to append
		// the file data to the already open bfd.
		// And trailing VSS data.
		if(bfd->mode!=BF_CLOSED
		  && (sb->cmd==CMD_FILE || sb->cmd==CMD_ENC_FILE
		      || sb->cmd==CMD_VSS_T || sb->cmd==CMD_ENC_VSS_T)
		  && bfd->path && !strcmp(bfd->path, fullpath))
		{
			return 1;
		}
#endif
		// If we have file data and the destination is
		// a fifo, it is OK to write to the fifo.
		if((sb->cmd==CMD_FILE || sb->cmd==CMD_ENC_FILE)
	  	  && S_ISFIFO(sb->statp.st_mode))
			return 1;

		// File path exists. Do not overwrite.
		if(!lstat(fullpath, &checkstat)) return 0;
	}

	return 1;
}

int do_restore_client_legacy(struct config *conf, enum action act, int vss_restore)
{
	int ars=0;
	int ret=0;
	int quit=0;
	char msg[512]="";
	struct sbufl sb;
	int wroteendcounter=0;
// Windows needs to have the VSS data written first, and the actual data
// written immediately afterwards. The server is transferring them in two
// chunks. So, leave bfd open after a Windows metadata transfer.
	BFILE bfd;
#ifdef HAVE_WIN32
	binit(&bfd, 0, conf);
#endif

	logp("doing %s\n", act_str(act));

	snprintf(msg, sizeof(msg), "%s %s:%s", act_str(act),
		conf->backup?conf->backup:"", conf->regex?conf->regex:"");
	if(async_write_str(CMD_GEN, msg)
	  || async_read_expect(CMD_GEN, "ok"))
		return -1;
	logp("doing %s confirmed\n", act_str(act));

	if(conf->send_client_counters)
	{
		if(recv_counters(conf))
			return -1;
	}

#if defined(HAVE_WIN32)
	if(act==ACTION_RESTORE) win32_enable_backup_privileges();
#endif

	init_sbufl(&sb);
	while(!quit)
	{
		char *fullpath=NULL;

		free_sbufl(&sb);
		if((ars=sbufl_fill(NULL, NULL, &sb, conf->cntr)))
		{
			if(ars<0) ret=-1;
			else
			{
				// ars==1 means it ended ok.
				print_endcounter(conf->cntr);
				print_filecounters(conf, act);
				wroteendcounter++;
				logp("got %s end\n", act_str(act));
				if(async_write_str(CMD_GEN, "restoreend ok"))
					ret=-1;
			}
			break;
		}

		switch(sb.cmd)
		{
			case CMD_DIRECTORY:
			case CMD_FILE:
			case CMD_ENC_FILE:
			case CMD_SOFT_LINK:
			case CMD_HARD_LINK:
			case CMD_SPECIAL:
			case CMD_METADATA:
			case CMD_ENC_METADATA:
			case CMD_VSS:
			case CMD_ENC_VSS:
			case CMD_VSS_T:
			case CMD_ENC_VSS_T:
			case CMD_EFS_FILE:
				if(conf->strip)
				{
					int s;
					s=strip_path_components(&sb, &(sb.path),
						conf);
					if(s<0) // error
					{
						ret=-1;
						quit++;
					}
					else if(s==0)
					{
						// Too many components stripped
						// - carry on.
						continue;
					}
					// It is OK, sb.path is now stripped.
				}
				if(!(fullpath=prepend_s(conf->restoreprefix,
					sb.path)))
				{
					log_and_send_oom(__FUNCTION__);
					ret=-1;
					quit++;
				}
				if(act==ACTION_RESTORE)
				{
				  strip_invalid_characters(&fullpath);
				  if(!overwrite_ok(&sb, conf, &bfd, fullpath))
				  {
					char msg[512]="";
					// Something exists at that path.
					snprintf(msg, sizeof(msg),
						"Path exists: %s", fullpath);
					if(restore_interrupt(&sb, msg, conf))
					{
						ret=-1;
						quit++;
					}
					else
					{
						if(fullpath) free(fullpath);
						continue;
					}
				  }
				}
				break;	
			default:
				break;
		}

		if(!quit && !ret) switch(sb.cmd)
		{
			case CMD_WARNING:
				do_filecounter(conf->cntr, sb.cmd, 1);
				printf("\n");
				logp("%s", sb.path);
				break;
			case CMD_DIRECTORY:
                                if(restore_dir(&sb, fullpath, act, conf))
				{
					ret=-1;
					quit++;
				}
				break;
			case CMD_FILE:
			case CMD_VSS_T:
				// Have it a separate statement to the
				// encrypted version so that encrypted and not
				// encrypted files can be restored at the
				// same time.
				if(restore_file_or_get_meta(&bfd, &sb,
					fullpath, act,
					NULL, NULL, NULL,
					vss_restore, conf))
				{
					logp("restore_file error\n");
					ret=-1;
					quit++;
				}
				break;
			case CMD_ENC_FILE:
			case CMD_ENC_VSS_T:
				if(restore_file_or_get_meta(&bfd, &sb,
					fullpath, act,
					conf->encryption_password,
					NULL, NULL, vss_restore, conf))
				{
					logp("restore_file error\n");
					ret=-1;
					quit++;
				}
				break;
			case CMD_SOFT_LINK:
			case CMD_HARD_LINK:
				if(restore_link(&sb, fullpath,
					conf->restoreprefix, act, conf))
				{
					ret=-1;
					quit++;
				}
				break;
			case CMD_SPECIAL:
				if(restore_special(&sb, fullpath, act, conf))
				{
					ret=-1;
					quit++;
				}
				break;
			case CMD_METADATA:
			case CMD_VSS:
				if(restore_metadata(&bfd, &sb, fullpath, act,
					NULL, vss_restore, conf))
				{
					ret=-1;
					quit++;
				}
				break;
			case CMD_ENC_METADATA:
			case CMD_ENC_VSS:
				if(restore_metadata(&bfd, &sb, fullpath, act,
					conf->encryption_password,
					vss_restore, conf))
				{
					ret=-1;
					quit++;
				}
				break;
			case CMD_EFS_FILE:
				if(restore_file_or_get_meta(&bfd, &sb,
					fullpath, act,
					NULL, NULL, NULL, vss_restore, conf))
				{
					logp("restore_file error\n");
					ret=-1;
					quit++;
				}
				break;
			default:
				logp("unknown cmd: %c\n", sb.cmd);
				quit++; ret=-1;
				break;
		}

		if(fullpath) free(fullpath);
	}
	free_sbufl(&sb);

#ifdef HAVE_WIN32
	// It is possible for a bfd to still be open.
	bclose(&bfd);
#endif

	if(!wroteendcounter)
	{
		print_endcounter(conf->cntr);
		print_filecounters(conf, act);
	}

	if(!ret) logp("%s finished\n", act_str(act));
	else logp("ret: %d\n", ret);

	return ret;
}
