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

static int restore_interrupt(char fcmd, const char *dpth, const char *msg, struct cntr *cntr)
{
	int ret=0;
	int quit=0;
	char *buf=NULL;

	do_filecounter(cntr, 'w', 1);
	logp("WARNING: %s\n", msg);
	if(async_write_str('w', msg)) return -1;
/* The following is now kludged in asyncio.c.
   TODO: Make the restore use sbuf so that it does not need to worry about
   parsing this stuff itself.
	if(fcmd=='l' || fcmd=='L')
	{
		char cmd;
		size_t len=0;
		char *buf=NULL;
		// It is a link - read the next line before returning.
		if(async_read(&cmd, &buf, &len))
		{
			if(buf) free(buf);
			return -1;
		}
		if(cmd!='l' && cmd!='L')
		{
			logp("expected link command when flushing - got: %c\n",
				cmd);
			if(buf) free(buf);
			return -1;
		}
		if(buf) free(buf);
	}
*/

	// If it is file data, get the server
	// to interrupt the flow and move on.
	if((fcmd!='f' && fcmd!='y') || !dpth) return 0;
	if(async_write_str('i', dpth))
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
	else
	{
		//printf("%s -> %s\n", fname, lnk);
		ret=symlink(lnk, fname);
	}
#endif

	if(ret) logp("could not %slink %s -> %s\n", cmd=='L'?"hard":"sym",
		fname, cmd=='L'?lnk:fname);

	return ret;
}

static int restore_file(char cmd, const char *fname, struct stat *statp, enum action act, const char *encpassword, struct cntr *cntr)
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
		do_filecounter(cntr, cmd, 1);
		return 0;
	}

	if(build_path(fname, "", len, &rpath))
	{
		char msg[256]="";
		// failed - do a warning
		snprintf(msg, sizeof(msg), "build path failed: %s", rpath);
		if(restore_interrupt(cmd, NULL, msg, cntr))
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
		if(restore_interrupt(cmd, NULL, msg, cntr))
			ret=-1;
	}
#else
	if(!(fp=open_file(rpath, "wb")))
	{
		char msg[256]="";
		snprintf(msg, sizeof(msg),
			"Could not open for writing %s: %s",
				rpath, strerror(errno));
		if(restore_interrupt(cmd, NULL, msg, cntr))
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
		if(!ret) set_attributes(rpath, cmd, statp);
#endif
		if(bytes) free(bytes);
		if(ret)
		{
			char msg[256]="";
			snprintf(msg, sizeof(msg),
				"Could not transfer file in: %s",
					rpath);
			if(restore_interrupt(cmd, NULL, msg, cntr))
				ret=-1;
		}
	}
	if(!ret) do_filecounter(cntr, cmd, 1);

	if(rpath) free(rpath);
	return ret;
}

static int restore_special(char cmd, const char *fname, struct stat *statp, enum action act, struct cntr *cntr)
{
	int ret=0;
#ifdef HAVE_WIN32
	logw(cntr, "Cannot restore special files to Windows: %s\n", fname);
#else
	char *rpath=NULL;

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
		if(restore_interrupt(cmd, NULL, msg, cntr))
			ret=-1;
	}
	if(S_ISFIFO(statp->st_mode))
	{
		if(mkfifo(rpath, statp->st_mode) && errno!=EEXIST)
		{
			char msg[256]="";
			snprintf(msg, sizeof(msg),
				"Cannot make fifo: %s\n", strerror(errno));
			logw(cntr, "%s", msg);
		}
		else
		{
			set_attributes(rpath, 's', statp);
			do_filecounter(cntr, 's', 1);
		}
	}
	else if(S_ISSOCK(statp->st_mode)) {
		char msg[256]="";
		snprintf(msg, sizeof(msg),
			"Skipping restore of socket: %s\n", fname);
		logw(cntr, "%s", msg);
#ifdef S_IFDOOR     // Solaris high speed RPC mechanism
	} else if (S_ISDOOR(statp->st_mode)) {
		char msg[256]="";
		snprintf(msg, sizeof(msg),
			"Skipping restore of door file: %s\n", fname);
		logw(cntr, "%s", msg);
#endif
#ifdef S_IFPORT     // Solaris event port for handling AIO
	} else if (S_ISPORT(statp->st_mode)) {
		char msg[256]="";
		snprintf(msg, sizeof(msg),
			"Skipping restore of event port file: %s\n", fname);
		logw(msg);
#endif
	} else {
            if(mknod(fname, statp->st_mode, statp->st_rdev) && errno!=EEXIST)
	    {
		char msg[256]="";
		snprintf(msg, sizeof(msg),
			"Cannot make node: %s\n", strerror(errno));
		logw(cntr, "%s", msg);
            }
	    else
	    {
		set_attributes(rpath, 's', statp);
		do_filecounter(cntr, 's', 1);
	    }
         }
#endif
	return ret;
}

static int restore_dir(char cmd, const char *dname, struct stat *statp, enum action act, struct cntr *cntr)
{
	int ret=0;
	if(act==ACTION_RESTORE)
	{
		char *rpath=NULL;

		if(build_path(dname, "", 0, &rpath))
		{
			char msg[256]="";
			// failed - do a warning
			snprintf(msg, sizeof(msg),
				"build path failed: %s", rpath);
			if(restore_interrupt(cmd, NULL, msg, cntr))
				ret=-1;
		}
		else if(!is_dir(rpath) && mkdir(rpath, 0777))
		{
			char msg[256]="";
			snprintf(msg, sizeof(msg), "mkdir error: %s",
				strerror(errno));
			// failed - do a warning
			if(restore_interrupt(cmd, NULL, msg, cntr))
				ret=-1;
		}
		else
		{
			set_attributes(rpath, cmd, statp);
		}
		if(!ret) do_filecounter(cntr, cmd, 1);
	}
	else do_filecounter(cntr, cmd, 1);
	return ret;
}

static int restore_link(char fcmd, const char *fname, size_t flen, struct stat *statp, const char *restoreprefix, enum action act, struct cntr *cntr)
{
	int ret=0;
	char lcmd;
	size_t llen=0;
	char *lname=NULL;

	// Read where the link points to.	
	if(async_read(&lcmd, &lname, &llen))
	{
		ret=-1;
	}
	else if(fcmd!=lcmd)
	{
		ret=-1;
		async_write_str('e', "link cmd mismatch");
	}
	else if(act==ACTION_RESTORE)
	{
		if(make_link(fname, lname, lcmd, restoreprefix, cntr))
		{
			// failed - do a warning
			if(restore_interrupt(fcmd, NULL, "could not create link", cntr))
				ret=-1;
		}
		else
		{
			set_attributes(fname, fcmd, statp);
		}
		if(!ret) do_filecounter(cntr, fcmd, 1);
	}
	else do_filecounter(cntr, fcmd, 1);
	if(lname) free(lname);
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
	char cmd;
	int ars=0;
	int ret=0;
	int quit=0;
	size_t len=0;
	char *buf=NULL;
	char msg[64]="";
	struct stat statp;
	char *statbuf=NULL;
	size_t slen=0;
	struct stat checkstat;
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

	while(!quit)
	{
		char *dpth=NULL;
		char *fullpath=NULL;

		if((ars=async_read_stat(NULL, NULL, &statbuf, &slen, &statp, &dpth, cntr)))
		{
			if(ars<0) ret=-1; // error
			else
			{
				ret=0; // finished ok
				end_filecounter(cntr, 1, act);
				wroteendcounter++;
				logp("got %s end\n", act_str(act));
				if(async_write_str('c', "restoreend ok"))
					ret=-1;
			}
			break;
		}
		if(async_read(&cmd, &buf, &len))
		{
			logp("async_read error\n");
			ret=-1;
			if(dpth) free(dpth);
			break;
		}
		switch(cmd)
		{
			case 'd':
			case 'f':
			case 'y':
			case 'l':
			case 'L':
			case 's':
				if(!(fullpath=prepend_s(restoreprefix,
					buf, strlen(buf))))
				{
					log_and_send("out of memory");
					ret=-1;
					quit++;
				}
				if(act==ACTION_RESTORE)
				{
				  strip_invalid_characters(&fullpath);
				  if(!forceoverwrite
				   && !S_ISDIR(statp.st_mode)
				   && !lstat(fullpath, &checkstat))
				  {
					char msg[512]="";
printf("got lstat on restore\n");
					// Something exists at that path.
					snprintf(msg, sizeof(msg),
						"Path exists: %s (%s)",
							fullpath, dpth);
					if(restore_interrupt(cmd, dpth, msg, cntr))
					{
						ret=-1;
						quit++;
					}
					else
					{
						if(dpth) free(dpth);
						if(fullpath) free(fullpath);
						if(statbuf) { free(statbuf); statbuf=NULL; }
						if(buf) free(buf);
						buf=NULL;
						continue;
					}
				  }
				}
				break;	
			default:
				break;
		}
		if(dpth) free(dpth);

		if(!quit && !ret) switch(cmd)
		{
			case 'w': // warning
				do_filecounter(cntr, cmd, 1);
				printf("\n");
				logp("%s", buf);
				break;
			case 'd': // directory data
                                if(restore_dir(cmd, fullpath, &statp, act, cntr))
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
				if(restore_file(cmd, fullpath, &statp, act,
					NULL, cntr))
				{
					logp("restore_file error\n");
					ret=-1;
					quit++;
				}
				break;
			case 'y': // file data (encrypted)
				if(restore_file(cmd, fullpath, &statp, act,
					conf->encryption_password, cntr))
				{
					logp("restore_file error\n");
					ret=-1;
					quit++;
				}
				break;
			case 'l': // symlink
			case 'L': // hardlink
				if(restore_link(cmd, fullpath, len,
					&statp, restoreprefix, act, cntr))
				{
					ret=-1;
					quit++;
				}
				break;
			case 's': // special file
				if(restore_special(cmd, fullpath, &statp,
					act, cntr))
				{
					ret=-1;
					quit++;
				}
				break;
			default:
				logp("unknown cmd: %c:%s\n", cmd, buf);
				quit++; ret=-1;
				break;
		}

		if(fullpath) free(fullpath);
		if(statbuf) { free(statbuf); statbuf=NULL; }
		if(buf) free(buf);
		buf=NULL;
	}
	if(statbuf) free(statbuf);

	if(!ret)
	{
		if(!wroteendcounter) end_filecounter(cntr, 1, act);
		logp("%s finished\n", act_str(act));
	}
	else logp("ret: %d\n", ret);

	return ret;
}
