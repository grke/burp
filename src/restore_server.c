#include "burp.h"
#include "prog.h"
#include "msg.h"
#include "lock.h"
#include "handy.h"
#include "asyncio.h"
#include "zlibio.h"
#include "counter.h"
#include "dpth.h"
#include "sbuf.h"
#include "regexp.h"
#include "current_backups_server.h"
#include "restore_server.h"

#include <librsync.h>

/*
static int inflate_or_link_oldfile(const char *oldpath, const char *infpath, int compression)
{
	int ret=0;
	struct stat statp;

	if(lstat(oldpath, &statp))
	{
		logp("could not lstat %s\n", oldpath);
		return -1;
	}

	if(dpth_is_compressed(compression, oldpath))
	{
		FILE *source=NULL;
		FILE *dest=NULL;

		//logp("inflating...\n");

		if(!(dest=open_file(infpath, "wb")))
		{
			close_fp(&dest);
			return -1;
		}

		if(!statp.st_size)
		{
			// Empty file - cannot inflate.
			// just close the destination and we have duplicated a
			// zero length file.
			logp("asked to inflate zero length file: %s\n", oldpath);
			close_fp(&dest);
			return 0;
		}

		if(!(source=open_file(oldpath, "rb")))
		{
			close_fp(&dest);
			return -1;
		}

		if((ret=zlib_inflate(source, dest))!=Z_OK)
			logp("zlib_inflate returned: %d\n", ret);

		close_fp(&source);
		if(close_fp(&dest))
		{
			logp("error closing %s in inflate_or_link_oldfile\n",
				dest);
			return -1;
		}
	}
	else
	{
		// Not compressed - just hard link it.
		if(link(oldpath, infpath))
		{
			logp("hardlink %s to %s failed: %s\n",
				infpath, oldpath, strerror(errno));
			ret=-1;
		}
	}
	return ret;
}
*/
/*
static int restore_sbuf(struct sbuf *sb, struct bu *arr, int a, int i, const char *tmppath1, const char *tmppath2, enum action act, const char *client, char status, struct config *cconf)
{
	//logp("%s: %s\n", act==ACTION_RESTORE?"restore":"verify", sb->path);
	return 0;
}
*/
/*
static int do_restore_end(enum action act, struct cntr *cntr)
{
	char cmd;
	int ret=0;
	int quit=0;
	size_t len=0;

	if(async_write_str(CMD_GEN, "restore_end"))
		ret=-1;

	while(!ret && !quit)
	{
		char *buf=NULL;
		if(async_read(&cmd, &buf, &len))
		{
			ret=-1; quit++;
		}
		else if(cmd==CMD_GEN && !strcmp(buf, "ok_restore_end"))
		{
			logp("got ok_restore_end\n");
			quit++;
		}
		else if(cmd==CMD_WARNING)
		{
			logp("WARNING: %s\n", buf);
			do_filecounter(cntr, cmd, 0);
		}
		else if(cmd==CMD_INTERRUPT)
		{
			// ignore - client wanted to interrupt a file
		}
		else
		{
			logp("unexpected cmd from client at end of restore: %c:%s\n", cmd, buf);
			ret=-1; quit++;
		}
		if(buf) { free(buf); buf=NULL; }
	}

	return ret;
}
*/
/*
static int restore_ent(const char *client, struct sbuf *sb, struct sbuf ***sblist, int *scount, struct bu *arr, int a, int i, const char *tmppath1, const char *tmppath2, enum action act, char status, struct config *cconf, struct cntr *cntr, struct cntr *p1cntr)
{
	int s=0;
	int ret=0;
	// Check if we have any directories waiting to be restored.
	for(s=(*scount)-1; s>=0; s--)
	{
		if(is_subdir((*sblist)[s]->path, sb->path))
		{
			// We are still in a subdir.
			//printf(" subdir (%s %s)\n",
			// (*sblist)[s]->path, sb->path);
			break;
		}
		else
		{
			// Can now restore sblist[s] because nothing else is
			// fiddling in a subdirectory.
			if(restore_sbuf((*sblist)[s], arr, a, i, tmppath1,
				tmppath2, act, client, status,
				p1cntr, cntr, cconf))
			{
				ret=-1;
				break;
			}
			else if(del_from_sbuf_arr(sblist, scount))
			{
				ret=-1;
				break;
			}
		}
	}

	// If it is a directory, need to remember it and restore it later, so
	//  that the permissions come out right.
	// Meta data of directories will also have the stat stuff set to be a
	/   directory, so will also come out at the end.
	if(!ret && S_ISDIR(sb->statp.st_mode))
	{
		if(add_to_sbuf_arr(sblist, sb, scount))
			ret=-1;

		// Wipe out sb, without freeing up all the strings inside it,
		// which have been added to sblist.
		init_sbuf(sb);
	}
	else if(!ret && restore_sbuf(sb, arr, a, i, tmppath1, tmppath2, act,
		client, status, p1cntr, cntr, cconf))
			ret=-1;
	return ret;
}
*/
/*
static int srestore_matches(struct strlist *s, const char *path)
{
	int r=0;
	if(!s->flag) return 0; // Do not know how to do excludes yet.
	if((r=strncmp(s->path, path, strlen(s->path)))) return 0; // no match
	if(!r) return 1; // exact match
	if(*(path+strlen(s->path)+1)=='/')
		return 1; // matched directory contents
	return 0; // no match
}
*/

/*
// Used when restore is initiated from the server.
static int check_srestore(struct config *cconf, const char *path)
{
	int i=0;
	for(i=0; i<cconf->iecount; i++)
	{
		//printf(" %d %s %s\n",
		//	cconf->incexcdir[i]->flag, cconf->incexcdir[i]->path,
		//	path);
		if(srestore_matches(cconf->incexcdir[i], path))
			return 1;
	}
	return 0;
}
*/

// a = length of struct bu array
// i = position to restore from
static int restore_manifest(struct bu *arr, int a, int i, const char *tmppath1, const char *tmppath2, regex_t *regex, int srestore, enum action act, const char *client, char **dir_for_notify, struct config *cconf)
{
	int ret=0;
	gzFile zp=NULL;
	char *manifest=NULL;
	char *datadir=NULL;
//	FILE *logfp=NULL;
	char *logpath=NULL;
	char *logpathz=NULL;
	// For sending status information up to the server.
//	char status=STATUS_RESTORING;

//	if(act==ACTION_RESTORE) status=STATUS_RESTORING;
//	else if(act==ACTION_VERIFY) status=STATUS_VERIFYING;

	if(
	    (act==ACTION_RESTORE && !(logpath=prepend_s(arr[i].path, "restorelog", strlen("restorelog"))))
	 || (act==ACTION_RESTORE && !(logpathz=prepend_s(arr[i].path, "restorelog.gz", strlen("restorelog.gz"))))
	 || (act==ACTION_VERIFY && !(logpath=prepend_s(arr[i].path, "verifylog", strlen("verifylog"))))
	 || (act==ACTION_VERIFY && !(logpathz=prepend_s(arr[i].path, "verifylog.gz", strlen("verifylog.gz"))))
	 || !(manifest=prepend_s(arr[i].path, "manifest.gz", strlen("manifest.gz"))))
	{
		log_and_send_oom(__FUNCTION__);
		ret=-1;
	}
	else if(set_logfp(logpath, cconf))
	{
		char msg[256]="";
		snprintf(msg, sizeof(msg),
			"could not open log file: %s", logpath);
		log_and_send(msg);
		ret=-1;
	}

	*dir_for_notify=strdup(arr[i].path);

	log_restore_settings(cconf, srestore);

	// First, do a pass through the manifest to set up the counters.
	if(!ret && !(zp=gzopen_file(manifest, "rb")))
	{
		log_and_send("could not open manifest");
		ret=-1;
	}
	else
	{
/*
		int ars=0;
		int quit=0;
		struct sbuf sb;
		init_sbuf(&sb);
		while(!quit)
		{
			if((ars=sbuf_fill(NULL, zp, &sb, cntr)))
			{
				if(ars<0) ret=-1;
				// ars==1 means end ok
				quit++;
			}
			else
			{
				if((!srestore
				    || check_srestore(cconf, sb.path))
				  && check_regex(regex, sb.path))
				{
					do_filecounter(p1cntr, sb.cmd, 0);
					if(sb.endfile)
					  do_filecounter_bytes(p1cntr,
                 			    strtoull(sb.endfile, NULL, 10));
				}
			}
			free_sbuf(&sb);
		}
		free_sbuf(&sb);
		gzclose_fp(&zp);
*/
	}

	if(cconf->send_client_counters)
	{
		if(send_counters(client, cconf))
		{
			ret=-1;
		}
	}

	// Now, do the actual restore.
	if(!ret && !(zp=gzopen_file(manifest, "rb")))
	{
		log_and_send("could not open manifest");
		ret=-1;
	}
	else
	{
/*
		char cmd;
		int s=0;
		int quit=0;
		size_t len=0;
		struct sbuf sb;
		// For out-of-sequence directory restoring so that the
		// timestamps come out right:
		int scount=0;
		struct sbuf **sblist=NULL;

		init_sbuf(&sb);

		while(!quit)
		{
			int ars=0;
			char *buf=NULL;
			if(async_read_quick(&cmd, &buf, &len))
			{
				logp("read quick error\n");
				ret=-1; quit++; break;
			}
			if(buf)
			{
				//logp("got read quick\n");
				if(cmd==CMD_WARNING)
				{
					logp("WARNING: %s\n", buf);
					do_filecounter(cntr, cmd, 0);
					free(buf); buf=NULL;
					continue;
				}
				else if(cmd==CMD_INTERRUPT)
				{
					// Client wanted to interrupt the
					// sending of a file. But if we are
					// here, we have already moved on.
					// Ignore.
					free(buf); buf=NULL;
					continue;
				}
				else
				{
					logp("unexpected cmd from client: %c:%s\n", cmd, buf);
					free(buf); buf=NULL;
					ret=-1; quit++; break;
				}
			}

			if((ars=sbuf_fill(NULL, zp, &sb, cntr)))
			{
				if(ars<0) ret=-1;
				// ars==1 means end ok
				quit++;
			}
			else
			{
				if((!srestore
				    || check_srestore(cconf, sb.path))
				  && check_regex(regex, sb.path)
				  && restore_ent(client,
					&sb, &sblist, &scount,
					arr, a, i, tmppath1, tmppath2,
					act, status, cconf,
					cntr, p1cntr))
				{
					ret=-1;
					quit++;
				}
			}
			free_sbuf(&sb);
		}
		gzclose_fp(&zp);
		// Restore any directories that are left in the list.
		if(!ret) for(s=scount-1; s>=0; s--)
		{
			if(restore_sbuf(sblist[s], arr, a, i,
				tmppath1, tmppath2, act, client, status,
				p1cntr, cntr, cconf))
			{
				ret=-1;
				break;
			}
		}
		free_sbufs(sblist, scount);

		if(!ret) ret=do_restore_end(act, cntr);

		//print_endcounter(cntr);
		print_filecounters(p1cntr, cntr, act);

		reset_filecounter(p1cntr, time(NULL));
		reset_filecounter(cntr, time(NULL));
*/
	}
	set_logfp(NULL, cconf);
	compress_file(logpath, logpathz, cconf);
	if(manifest) free(manifest);
	if(datadir) free(datadir);
	if(logpath) free(logpath);
	if(logpathz) free(logpathz);
	return ret;
}

int do_restore_server(const char *basedir, enum action act, const char *client, int srestore, char **dir_for_notify, struct config *cconf)
{
	int a=0;
	int i=0;
	int ret=0;
	int found=0;
	struct bu *arr=NULL;
	unsigned long index=0;
	char *tmppath1=NULL;
	char *tmppath2=NULL;
	regex_t *regex=NULL;

	logp("in do_restore\n");

	if(compile_regex(&regex, cconf->regex)) return -1;

	if(!(tmppath1=prepend_s(basedir, "tmp1", strlen("tmp1")))
	  || !(tmppath2=prepend_s(basedir, "tmp2", strlen("tmp2"))))
	{
		if(tmppath1) free(tmppath1);
		if(regex) { regfree(regex); free(regex); }
		return -1;
	}

	if(get_current_backups(basedir, &arr, &a, 1))
	{
		if(tmppath1) free(tmppath1);
		if(tmppath2) free(tmppath2);
		if(regex) { regfree(regex); free(regex); }
		return -1;
	}

	if(!(index=strtoul(cconf->backup, NULL, 10)) && a>0)
	{
		// No backup specified, do the most recent.
		ret=restore_manifest(arr, a, a-1,
			tmppath1, tmppath2, regex, srestore, act, client,
			dir_for_notify, cconf);
		found=TRUE;
	}

	if(!found) for(i=0; i<a; i++)
	{
		if(!strcmp(arr[i].timestamp, cconf->backup)
			|| arr[i].index==index)
		{
			found=TRUE;
			//logp("got: %s\n", arr[i].path);
			ret|=restore_manifest(arr, a, i,
				tmppath1, tmppath2, regex,
				srestore, act, client, dir_for_notify, cconf);
			break;
		}
	}

	free_current_backups(&arr, a);

	if(!found)
	{
		logp("backup not found\n");
		async_write_str(CMD_ERROR, "backup not found");
		ret=-1;
	}
	if(tmppath1)
	{
		unlink(tmppath1);
		free(tmppath1);
	}
	if(tmppath2)
	{
		unlink(tmppath2);
		free(tmppath2);
	}
	if(regex)
	{
		regfree(regex);
		free(regex);
	}
	return ret;
}
