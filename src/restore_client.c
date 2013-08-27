#include "burp.h"
#include "prog.h"
#include "msg.h"
#include "lock.h"
#include "handy.h"
#include "asyncio.h"
#include "counter.h"
#include "berrno.h"
#include "client_vss.h"
#include "restore_client.h"
#include "forkchild.h"
#include "sbuf.h"
#include "dpth.h"
#include "extrameta.h"
#include "attribs.h"

static int restore_interrupt(struct sbuf *sb, const char *msg, struct config *conf)
{
	return 0;
/* FIX THIS
	int ret=0;
	int quit=0;
	char *buf=NULL;

	if(!conf->cntr) return 0;

	do_filecounter(conf->cntr, CMD_WARNING, 1);
	logp("WARNING: %s\n", msg);
	if(async_write_str(CMD_WARNING, msg)) return -1;

	// If it is file data, get the server
	// to interrupt the flow and move on.
	if(sb->cmd!=CMD_FILE
	   && sb->cmd!=CMD_ENC_FILE
	   && sb->cmd!=CMD_EFS_FILE)
		return 0;

	if(async_write_str(CMD_INTERRUPT, sb->path))
	{
		ret=-1;
		quit++;
	}
	// Read to the end file marker.
	while(!quit)
	{
		size_t len=0;
		char cmd='\0';
		if(async_read(&cmd, &buf, &len))
		{
			ret=-1; quit++;
		}
		if(!ret && len)
		{
		  if(cmd==CMD_APPEND)
		  {
			continue;
		  }
		  else if(cmd==CMD_END_FILE)
		  {
			break;
		  }
		  else
		  {
			logp("unexpected cmd from server while flushing: %c:%s\n", cmd, buf);
			ret=-1; quit++;
		  }
		}
		if(buf) { free(buf); buf=NULL; }
	}
	if(buf) free(buf);
	return ret;
*/
}

static int make_link(const char *fname, const char *lnk, char cmd, struct config *conf)
{
	int ret=-1;

#ifdef HAVE_WIN32
	logw(conf->cntr, "windows seems not to support hardlinks or symlinks\n");
#else
	unlink(fname);
	if(cmd==CMD_HARD_LINK)
	{
		char *flnk=NULL;
		if(!(flnk=prepend_s(conf->restoreprefix, lnk, strlen(lnk))))
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

static int open_for_restore(
	BFILE *bfd,
	const char *path,
	struct sbuf *sb,
	int vss_restore,
	struct config *conf)
{
	bclose(bfd);
	binit(bfd, sb->winattr, conf);
#ifdef HAVE_WIN32
	if(vss_restore)
		set_win32_backup(bfd);
	else
		bfd->use_backup_api=0;
#endif
	if(bopen(bfd, path,
		O_WRONLY | O_CREAT | O_TRUNC | O_BINARY,
		S_IRUSR | S_IWUSR)<=0)
	{
		berrno be;
		char msg[256]="";
		snprintf(msg, sizeof(msg), "Could not open for writing %s: %s",
			path, be.bstrerror(errno));
		if(restore_interrupt(sb, msg, conf))
			return -1;
	}
	// Add attributes to bfd so that they can be set when it is closed.
	bfd->winattr=sb->winattr;
	memcpy(&bfd->statp, &sb->statp, sizeof(struct stat));
	return 0;
}

static int start_restore_file(
	BFILE *bfd,
	struct sbuf *sb,
	const char *fname,
	enum action act,
	const char *encpassword,
	char **metadata,
	size_t *metalen,
	int vss_restore,
	struct config *conf)
{
	int ret=-1;
	size_t len=0;
	char *rpath=NULL;

	if(act==ACTION_VERIFY)
	{
		do_filecounter(conf->cntr, sb->cmd, 1);
		return 0;
	}

	if(build_path(fname, "", len, &rpath, NULL))
	{
		char msg[256]="";
		// failed - do a warning
		snprintf(msg, sizeof(msg), "build path failed: %s", fname);
		if(restore_interrupt(sb, msg, conf))
			ret=-1;
		ret=0; // Try to carry on with other files.
		goto end;
	}

	if(open_for_restore(bfd, rpath, sb, vss_restore, conf))
		goto end;

	do_filecounter(conf->cntr, sb->cmd, 1);

	ret=0;
end:
	if(rpath) free(rpath);
	return ret;
}

static int restore_special(struct sbuf *sb, const char *fname, enum action act, struct config *conf)
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

	if(build_path(fname, "", 0, &rpath, NULL))
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
			attribs_set(rpath, &statp, sb->winattr, conf);
			do_filecounter(conf->cntr, CMD_SPECIAL, 1);
		}
//	}
//	else if(S_ISSOCK(statp.st_mode)) {
//		char msg[256]="";
//		snprintf(msg, sizeof(msg),
//			"Skipping restore of socket: %s\n", fname);
//		logw(conf->cntr, "%s", msg);
//
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
		attribs_set(rpath, &statp, sb->winattr, conf);
		do_filecounter(conf->cntr, CMD_SPECIAL, 1);
	    }
         }
#endif
end:
	if(rpath) free(rpath);
	return ret;
}

static int restore_dir(struct sbuf *sb, const char *dname, enum action act, struct config *conf)
{
	int ret=0;
	char *rpath=NULL;
	if(act==ACTION_RESTORE)
	{
		if(build_path(dname, "", 0, &rpath, NULL))
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
			attribs_set(rpath, &(sb->statp), sb->winattr, conf);
		}
		if(!ret) do_filecounter(conf->cntr, sb->cmd, 1);
	}
	else do_filecounter(conf->cntr, sb->cmd, 1);
end:
	if(rpath) free(rpath);
	return ret;
}

static int restore_link(struct sbuf *sb, const char *fname, enum action act, struct config *conf)
{
	int ret=0;

	if(act==ACTION_RESTORE)
	{
		char *rpath=NULL;
		if(build_path(fname, "", strlen(fname), &rpath, NULL))
		{
			char msg[256]="";
			// failed - do a warning
			snprintf(msg, sizeof(msg), "build path failed: %s",
				fname);
			if(restore_interrupt(sb, msg, conf))
				ret=-1;
			goto end;
		}
		else if(make_link(fname, sb->linkto, sb->cmd, conf))
		{
			// failed - do a warning
			if(restore_interrupt(sb, "could not create link", conf))
				ret=-1;
			goto end;
		}
		else if(!ret)
		{
			attribs_set(fname, &(sb->statp), sb->winattr, conf);
			do_filecounter(conf->cntr, sb->cmd, 1);
		}
		if(rpath) free(rpath);
	}
	else do_filecounter(conf->cntr, sb->cmd, 1);
end:
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
	struct config *conf)
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
			attribs_set(fname, &(sb->statp), sb->winattr, conf);
#endif
			do_filecounter(conf->cntr, sb->cmd, 1);
		}
	}
	else do_filecounter(conf->cntr, sb->cmd, 1);
	return 0;
}
*/

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

// Return 1 for ok, -1 for error, 0 for too many components stripped.
static int strip_path_components(struct sbuf *sb, struct config *conf)
{
	int s=0;
	char *tmp=NULL;
	char *cp=sb->path;
	char *dp=NULL;
	int strip=conf->strip;
	for(s=0; cp && *cp && s<strip; s++)
	{
		if(!(dp=strchr(cp, '/')))
		{
			char msg[256]="";
			snprintf(msg, sizeof(msg),
				"Stripped too many components: %s", sb->path);
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
			"Stripped too many components: %s", sb->path);
		if(restore_interrupt(sb, msg, conf))
			return -1;
		return 0;
	}
	if(!(tmp=strdup(cp)))
	{
		log_and_send_oom(__FUNCTION__);
		return -1;
	}
	free(sb->path);
	sb->path=tmp;
	return 1;
}

static int overwrite_ok(struct sbuf *sb,
	struct config *conf,
#ifdef HAVE_WIN32
	BFILE *bfd,
#endif
	const char *fullpath)
{
	struct stat checkstat;

	// User specified overwrite is OK.
#ifdef HAVE_WIN32
	if(conf->overwrite) return 1;
#else
	// User specified overwrite is OK,
	if(conf->overwrite) return 1;
#endif

	if(!S_ISDIR(sb->statp.st_mode)
	  && sb->cmd!=CMD_METADATA
	  && sb->cmd!=CMD_ENC_METADATA)
	{
#ifdef HAVE_WIN32
		// If Windows previously got some VSS data, it needs to append
		// the file data to the already open bfd.
		if(bfd->mode!=BF_CLOSED
		  && (sb->cmd==CMD_FILE || sb->cmd==CMD_ENC_FILE)
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

static int write_data(BFILE *bfd, struct blk *blk)
{
	if(bfd->mode==BF_CLOSED)
		logp("Got data without an open file\n");
	else
	{
		int w;
//printf("writing: %d\n", blk->length);
		if((w=bwrite(bfd, blk->data, blk->length))<=0)
		{
			logp("error when appending %d: %d\n", blk->length, w);
			async_write_str(CMD_ERROR, "write failed");
			return -1;
		}
	}
	return 0;
}

int do_restore_client(struct config *conf, enum action act, int vss_restore)
{
	int ars=0;
	int ret=-1;
	char msg[512]="";
	struct sbuf *sb=NULL;
	struct blk *blk=NULL;
	int wroteendcounter=0;
	BFILE bfd;
	binit(&bfd, 0, conf);
	char *fullpath=NULL;

	logp("doing %s\n", act_str(act));

	snprintf(msg, sizeof(msg), "%s %s:%s", act_str(act),
		conf->backup?conf->backup:"", conf->regex?conf->regex:"");
	if(async_write_str(CMD_GEN, msg)
	  || async_read_expect(CMD_GEN, "ok"))
		goto end;
	logp("doing %s confirmed\n", act_str(act));

	if(conf->send_client_counters && recv_counters(conf))
		goto end;

#if defined(HAVE_WIN32)
	if(act==ACTION_RESTORE) win32_enable_backup_privileges();
#endif

	if(!(sb=sbuf_alloc())
	  || !(blk=blk_alloc()))
	{
		log_and_send_oom(__FUNCTION__);
		goto end;
	}

	while(1)
	{
		if((ars=sbuf_fill_from_net(sb, blk, conf)))
		{
			if(ars<0) goto end;
			// ars==1 means it ended ok.
			print_endcounter(conf->cntr);
			print_filecounters(conf, act);
			wroteendcounter++;
			logp("got %s end\n", act_str(act));
			if(async_write_str(CMD_GEN, "ok_restore_end"))
				goto end;
			break;
		}

		if(blk->data)
		{
			int wret;
			wret=write_data(&bfd, blk);
			free(blk->data);
			blk->data=NULL;
			if(wret) goto end;
			continue;
		}

		switch(sb->cmd)
		{
			case CMD_DIRECTORY:
			case CMD_FILE:
			case CMD_ENC_FILE:
			case CMD_SOFT_LINK:
			case CMD_HARD_LINK:
			case CMD_SPECIAL:
			case CMD_METADATA:
			case CMD_ENC_METADATA:
			case CMD_EFS_FILE:
				if(conf->strip)
				{
					int s;
					s=strip_path_components(sb, conf);
					if(s<0) goto end;
					if(s==0)
					{
						// Too many components stripped
						// - carry on.
						continue;
					}
					// It is OK, sb.path is now stripped.
				}
				if(fullpath) free(fullpath);
				if(!(fullpath=prepend_s(conf->restoreprefix,
					sb->path, strlen(sb->path))))
				{
					log_and_send_oom(__FUNCTION__);
					goto end;
				}
				if(act==ACTION_RESTORE)
				{
				  strip_invalid_characters(&fullpath);
				  if(!overwrite_ok(sb, conf,
#ifdef HAVE_WIN32
					&bfd,
#endif
					fullpath))
				  {
					char msg[512]="";
					// Something exists at that path.
					snprintf(msg, sizeof(msg),
						"Path exists: %s", fullpath);
					if(restore_interrupt(sb, msg, conf))
						goto end;
					else
						continue;
				  }
				}
				break;	
			default:
				break;
		}

		switch(sb->cmd)
		{
			case CMD_DIRECTORY:
                                if(restore_dir(sb, fullpath, act, conf))
					goto end;
				break;
			case CMD_FILE:
				// Have it a separate statement to the
				// encrypted version so that encrypted and not
				// encrypted files can be restored at the
				// same time.
				if(start_restore_file(
					&bfd, sb, fullpath, act,
					NULL, NULL, NULL,
					vss_restore, conf))
				{
					logp("restore_file error\n");
					goto end;
				}
				continue;
/* FIX THIS: Encryption currently not working.
			case CMD_ENC_FILE:
				if(start_restore_file(
					&bfd, sb, fullpath, act,
					conf->encryption_password,
					NULL, NULL, vss_restore, conf))
				{
					logp("restore_file error\n");
					goto end;
				}
				break;
*/
			case CMD_SOFT_LINK:
			case CMD_HARD_LINK:
				if(restore_link(sb, fullpath, act, conf))
					goto end;
				break;
			case CMD_SPECIAL:
				if(restore_special(sb, fullpath, act, conf))
					goto end;
				break;
/* FIX THIS: Metadata and EFS not supported yet.
			case CMD_METADATA:
				if(restore_metadata(
					&bfd, sb, fullpath, act,
					NULL, vss_restore, conf))
						goto end;
				break;
			case CMD_ENC_METADATA:
				if(restore_metadata(
					&bfd, sb, fullpath, act,
					conf->encryption_password,
					vss_restore, conf))
						goto end;
				break;
			case CMD_EFS_FILE:
				if(start_restore_file(
					&bfd, sb,
					fullpath, act,
					NULL,
					NULL, NULL, vss_restore, conf))
				{
					logp("restore_file error\n");
					goto end;
				}
				break;
*/
			default:
				logp("unknown cmd: %c\n", sb->cmd);
				goto end;
		}
		sbuf_free_contents(sb);
	}

	ret=0;
end:
	// It is possible for a fd to still be open.
	bclose(&bfd);

	if(!wroteendcounter)
	{
		print_endcounter(conf->cntr);
		print_filecounters(conf, act);
	}

	if(!ret) logp("%s finished\n", act_str(act));
	else logp("ret: %d\n", ret);

	sbuf_free(sb);

	return ret;
}
