#include "burp.h"
#include "prog.h"
#include "msg.h"
#include "rs_buf.h"
#include "lock.h"
#include "handy.h"
#include "asyncio.h"
#include "counter.h"
#include "berrno.h"
#include "client_vss.h"
#include "restore_client.h"
#include "forkchild.h"
#include "sbuf.h"

static int restore_interrupt(struct sbuf *sb, const char *msg, struct cntr *cntr)
{
	int ret=0;
	int quit=0;
	char *buf=NULL;

	do_filecounter(cntr, 'w', 1);
	logp("WARNING: %s\n", msg);
	if(async_write_str('w', msg)) return -1;

	// If it is file data, get the server
	// to interrupt the flow and move on.
	if((!sbuf_is_file(sb) && !sbuf_is_encrypted_file(sb)) || !(sb->datapth))
		return 0;

	if(async_write_str('i', sb->datapth))
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
		  if(cmd=='a')
		  {
			continue;
		  }
		  else if(cmd=='x')
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
}

static int make_link(const char *fname, const char *lnk, char cmd, const char *restoreprefix, struct cntr *cntr)
{
	int ret=-1;

#ifdef HAVE_WIN32
	logw(cntr, "windows seems not to support hardlinks or symlinks\n");
#else
	unlink(fname);
	if(cmd=='L')
	{
		char *flnk=NULL;
		if(!(flnk=prepend_s(restoreprefix, lnk, strlen(lnk))))
		{
			logp("out of memory\n");
			return -1;
		}
		//printf("%s -> %s\n", fname, flnk);
		ret=link(flnk, fname);
		free(flnk);
	}
	else if(cmd=='l')
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

	if(ret) logp("could not %slink %s -> %s: %s\n", cmd=='L'?"hard":"sym",
		fname, lnk, strerror(errno));

	return ret;
}

static int restore_file(struct sbuf *sb, const char *fname, enum action act, const char *encpassword, struct cntr *cntr)
{
	size_t len=0;
	int ret=0;
	char *rpath=NULL;
#ifdef HAVE_WIN32
	int bopenret;
	BFILE bfd;
#else
	FILE *fp=NULL;
#endif
	if(act==ACTION_VERIFY)
	{
		do_filecounter(cntr, sb->cmd, 1);
		return 0;
	}

	if(build_path(fname, "", len, &rpath))
	{
		char msg[256]="";
		// failed - do a warning
		snprintf(msg, sizeof(msg), "build path failed: %s", rpath);
		if(restore_interrupt(sb, msg, cntr))
			ret=-1;
	}

#ifdef HAVE_WIN32
	binit(&bfd);
	set_win32_backup(&bfd);
	if(S_ISDIR(statp->st_mode))
	{
		mkdir(rpath, 0777);
		bopenret=bopen(&bfd, rpath, O_WRONLY | O_BINARY, 0);
	}
	else
		bopenret=bopen(&bfd, rpath,
		  O_WRONLY | O_CREAT | O_TRUNC | O_BINARY, S_IRUSR | S_IWUSR);
	if(bopenret<0)
	{
		berrno be;
		char msg[256]="";
		snprintf(msg, sizeof(msg),
			"Could not open for writing %s: %s",
				rpath, be.bstrerror(errno));
		if(restore_interrupt(sb, msg, cntr))
			ret=-1;
	}
#else
	if(!(fp=open_file(rpath, "wb")))
	{
		char msg[256]="";
		snprintf(msg, sizeof(msg),
			"Could not open for writing %s: %s",
				rpath, strerror(errno));
		if(restore_interrupt(sb, msg, cntr))
			ret=-1;
	}
#endif

	if(!ret)
	{
		char *bytes=NULL;
#ifdef HAVE_WIN32
		ret=transfer_gzfile_in(&bfd, NULL, &bytes, encpassword, cntr);
		bclose(&bfd);
#else
		ret=transfer_gzfile_in(NULL, fp, &bytes, encpassword, cntr);
		close_fp(&fp);
		if(!ret) set_attributes(rpath, sb->cmd, &(sb->statp));
#endif
		if(bytes) free(bytes);
		if(ret)
		{
			char msg[256]="";
			snprintf(msg, sizeof(msg),
				"Could not transfer file in: %s",
					rpath);
			if(restore_interrupt(sb, msg, cntr))
				ret=-1;
		}
	}
	if(!ret) do_filecounter(cntr, sb->cmd, 1);

	if(rpath) free(rpath);
	return ret;
}

static int restore_special(struct sbuf *sb, const char *fname, enum action act, struct cntr *cntr)
{
	int ret=0;
	char *rpath=NULL;
	struct stat statp=sb->statp;
#ifdef HAVE_WIN32
	logw(cntr, "Cannot restore special files to Windows: %s\n", fname);
#else

	if(act==ACTION_VERIFY)
	{
		do_filecounter(cntr, 's', 1);
		return 0;
	}

	if(build_path(fname, "", 0, &rpath))
	{
		char msg[256]="";
		// failed - do a warning
		snprintf(msg, sizeof(msg), "build path failed: %s", rpath);
		if(restore_interrupt(sb, msg, cntr))
			ret=-1;
	}
	if(S_ISFIFO(statp.st_mode))
	{
		if(mkfifo(rpath, statp.st_mode) && errno!=EEXIST)
		{
			char msg[256]="";
			snprintf(msg, sizeof(msg),
				"Cannot make fifo: %s\n", strerror(errno));
			logw(cntr, "%s", msg);
		}
		else
		{
			set_attributes(rpath, 's', &statp);
			do_filecounter(cntr, 's', 1);
		}
	}
	else if(S_ISSOCK(statp.st_mode)) {
		char msg[256]="";
		snprintf(msg, sizeof(msg),
			"Skipping restore of socket: %s\n", fname);
		logw(cntr, "%s", msg);
#ifdef S_IFDOOR     // Solaris high speed RPC mechanism
	} else if (S_ISDOOR(statp.st_mode)) {
		char msg[256]="";
		snprintf(msg, sizeof(msg),
			"Skipping restore of door file: %s\n", fname);
		logw(cntr, "%s", msg);
#endif
#ifdef S_IFPORT     // Solaris event port for handling AIO
	} else if (S_ISPORT(statp.st_mode)) {
		char msg[256]="";
		snprintf(msg, sizeof(msg),
			"Skipping restore of event port file: %s\n", fname);
		logw(cntr, "%s", msg);
#endif
	} else {
            if(mknod(fname, statp.st_mode, statp.st_rdev) && errno!=EEXIST)
	    {
		char msg[256]="";
		snprintf(msg, sizeof(msg),
			"Cannot make node: %s\n", strerror(errno));
		logw(cntr, "%s", msg);
            }
	    else
	    {
		set_attributes(rpath, 's', &statp);
		do_filecounter(cntr, 's', 1);
	    }
         }
#endif
	if(rpath) free(rpath);
	return ret;
}

static int restore_dir(struct sbuf *sb, const char *dname, enum action act, struct cntr *cntr)
{
	int ret=0;
	char *rpath=NULL;
	if(act==ACTION_RESTORE)
	{
		if(build_path(dname, "", 0, &rpath))
		{
			char msg[256]="";
			// failed - do a warning
			snprintf(msg, sizeof(msg),
				"build path failed: %s", rpath);
			if(restore_interrupt(sb, msg, cntr))
				ret=-1;
		}
		else if(!is_dir(rpath))
		{
			if(mkdir(rpath, 0777))
			{
				char msg[256]="";
				snprintf(msg, sizeof(msg), "mkdir error: %s",
					strerror(errno));
				// failed - do a warning
				if(restore_interrupt(sb, msg, cntr))
					ret=-1;
			}
		}
		else
		{
			set_attributes(rpath, sb->cmd, &(sb->statp));
		}
		if(!ret) do_filecounter(cntr, sb->cmd, 1);
	}
	else do_filecounter(cntr, sb->cmd, 1);
	if(rpath) free(rpath);
	return ret;
}

static int restore_link(struct sbuf *sb, const char *fname, const char *restoreprefix, enum action act, struct cntr *cntr)
{
	int ret=0;

	if(act==ACTION_RESTORE)
	{
		char *rpath=NULL;
		if(build_path(fname, "", strlen(fname), &rpath))
		{
			char msg[256]="";
			// failed - do a warning
			snprintf(msg, sizeof(msg), "build path failed: %s",
				rpath);
			if(restore_interrupt(sb, msg, cntr))
				ret=-1;
		}
		else if(make_link(fname, sb->linkto, sb->cmd,
			restoreprefix, cntr))
		{
			// failed - do a warning
			if(restore_interrupt(sb, "could not create link", cntr))
				ret=-1;
		}
		else if(!ret)
		{
			set_attributes(fname, sb->cmd, &(sb->statp));
			do_filecounter(cntr, sb->cmd, 1);
		}
		if(rpath) free(rpath);
	}
	else do_filecounter(cntr, sb->cmd, 1);
	return ret;
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

int do_restore_client(struct config *conf, enum action act, const char *backup, const char *restoreprefix, const char *restoreregex, int forceoverwrite, struct cntr *cntr)
{
	int ars=0;
	int ret=0;
	int quit=0;
	char msg[64]="";
	struct stat checkstat;
	struct sbuf sb;
	int wroteendcounter=0;

	logp("doing %s\n", act_str(act));
	reset_filecounter(cntr);

	snprintf(msg, sizeof(msg), "%s %s:%s", act_str(act),
		backup?backup:"", restoreregex?restoreregex:"");
	if(async_write_str('c', msg)
	  || async_read_expect('c', "ok"))
		return -1;
	logp("doing %s confirmed\n", act_str(act));

#if defined(HAVE_WIN32)
	if(act==ACTION_RESTORE)
		win32_enable_backup_privileges(1 /* ignore_errors */);
#endif

	init_sbuf(&sb);
	while(!quit)
	{
		char *fullpath=NULL;

		free_sbuf(&sb);
		if((ars=sbuf_fill(NULL, NULL, &sb, cntr)))
		{
			if(ars<0) ret=-1;
			else
			{
				// ars==1 means it ended ok.
				end_filecounter(cntr, 1, act);
				wroteendcounter++;
				logp("got %s end\n", act_str(act));
				if(async_write_str('c', "restoreend ok"))
					ret=-1;
			}
			break;
		}

		switch(sb.cmd)
		{
			case 'd':
			case 'f':
			case 'y':
			case 'l':
			case 'L':
			case 's':
				if(!(fullpath=prepend_s(restoreprefix,
					sb.path, strlen(sb.path))))
				{
					log_and_send("out of memory");
					ret=-1;
					quit++;
				}
				if(act==ACTION_RESTORE)
				{
				  strip_invalid_characters(&fullpath);
				  if(!forceoverwrite
				   && !S_ISDIR(sb.statp.st_mode)
				   && !lstat(fullpath, &checkstat)
				// If we have file data and the destination is
				// a fifo, it is OK to write to the fifo.
				   && !((sbuf_is_file(&sb)
					  || sbuf_is_encrypted_file(&sb))
					&& S_ISFIFO(checkstat.st_mode)))
				  {
					char msg[512]="";
					// Something exists at that path.
					snprintf(msg, sizeof(msg),
						"Path exists: %s (%s)",
							fullpath, sb.datapth);
					if(restore_interrupt(&sb, msg, cntr))
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
			case 'w': // warning
				do_filecounter(cntr, sb.cmd, 1);
				printf("\n");
				logp("%s", sb.path);
				break;
			case 'd': // directory data
                                if(restore_dir(&sb, fullpath, act, cntr))
				{
					ret=-1;
					quit++;
				}
				break;
			case 'f': // file data
				// Have it a separate statement to the
				// encrypted version so that encrypted and not
				// encrypted files can be restored at the
				// same time.
				if(restore_file(&sb, fullpath, act,
					NULL, cntr))
				{
					logp("restore_file error\n");
					ret=-1;
					quit++;
				}
				break;
			case 'y': // file data (encrypted)
				if(restore_file(&sb, fullpath, act,
					conf->encryption_password, cntr))
				{
					logp("restore_file error\n");
					ret=-1;
					quit++;
				}
				break;
			case 'l': // symlink
			case 'L': // hardlink
				if(restore_link(&sb, fullpath,
					restoreprefix, act, cntr))
				{
					ret=-1;
					quit++;
				}
				break;
			case 's': // special file
				if(restore_special(&sb, fullpath, act, cntr))
				{
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
	free_sbuf(&sb);

	if(!wroteendcounter) end_filecounter(cntr, 1, act);

	if(!ret) logp("%s finished\n", act_str(act));
	else logp("ret: %d\n", ret);

	return ret;
}
