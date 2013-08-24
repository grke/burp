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
#include "blk.h"
#include "regexp.h"
#include "current_backups_server.h"
#include "restore_server.h"

#include <librsync.h>

static int restore_sbuf(struct sbuf *sb, struct bu *arr, int a, int i, enum action act, const char *client, char status, struct config *conf)
{
	//logp("%s: %s\n", act==ACTION_RESTORE?"restore":"verify", sb->path);
	write_status(client, status, sb->path, conf);

	switch(sb->cmd)
	{
		case CMD_FILE:
		case CMD_ENC_FILE:
		case CMD_METADATA:
		case CMD_ENC_METADATA:
		case CMD_EFS_FILE:
			if(async_write(CMD_ATTRIBS, sb->attribs, sb->alen)
			  || async_write(sb->cmd, sb->path, sb->plen))
				return -1;
			return 0;
		default:
			if(async_write(CMD_ATTRIBS, sb->attribs, sb->alen))
				return -1;
			if(async_write(sb->cmd, sb->path, sb->plen))
				return -1;
			// If it is a link, send what
			// it points to.
			else if(sbuf_is_link(sb))
			{
				if(async_write(sb->cmd, sb->linkto, sb->llen))
					return -1;
			}
			do_filecounter(conf->cntr, sb->cmd, 0);
			return 0;
	}
}

static int do_restore_end(enum action act, struct config *conf)
{
	char cmd;
	int ret=-1;
	size_t len=0;

	if(async_write_str(CMD_GEN, "restore_end")) goto end;

	while(1)
	{
		char *buf=NULL;
		if(async_read(&cmd, &buf, &len))
			goto end;
		else if(cmd==CMD_GEN && !strcmp(buf, "ok_restore_end"))
		{
			//logp("got ok_restore_end\n");
			break;
		}
		else if(cmd==CMD_WARNING)
		{
			logp("WARNING: %s\n", buf);
			do_filecounter(conf->cntr, cmd, 0);
		}
		else if(cmd==CMD_INTERRUPT)
		{
			// ignore - client wanted to interrupt a file
		}
		else
		{
			logp("unexpected cmd from client at end of restore: %c:%s\n", cmd, buf);
			goto end;
		}
		if(buf) { free(buf); buf=NULL; }
	}
	ret=0;
end:
	return ret;
}

static int restore_ent(const char *client,
	struct sbuf **sb,
	struct slist *slist,
	struct bu *arr,
	int a,
	int i,
	enum action act,
	char status,
	struct config *conf)
{
	int ret=-1;
	struct sbuf *xb;

	//printf("want to restore: %s\n", sb->path);

	// Check if we have any directories waiting to be restored.
	while((xb=slist->head))
	{
		if(is_subdir(xb->path, (*sb)->path))
		{
			// We are still in a subdir.
			break;
		}
		else
		{
			// Can now restore because nothing else is
			// fiddling in a subdirectory.
			if(restore_sbuf(xb, arr, a, i, act, client, status,
				conf)) goto end;
			slist->head=xb->next;
			sbuf_free(xb);
		}
	}

	// If it is a directory, need to remember it and restore it later, so
	// that the permissions come out right.
	// Meta data of directories will also have the stat stuff set to be a
	// directory, so will also come out at the end.
	if(S_ISDIR((*sb)->statp.st_mode))
	{
		// Add to the head of the list instead of the tail.
		(*sb)->next=slist->head;
		slist->head=*sb;

		// Allocate a new sb.
		if(!(*sb=sbuf_alloc())) goto end;
	}
	else
		if(restore_sbuf(*sb, arr, a, i, act, client, status, conf))
			goto end;
	ret=0;
end:
	return ret;
}

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

// Used when restore is initiated from the server.
static int check_srestore(struct config *conf, const char *path)
{
	int i=0;
	for(i=0; i<conf->iecount; i++)
	{
		//printf(" %d %s %s\n",
		//	conf->incexcdir[i]->flag, conf->incexcdir[i]->path,
		//	path);
		if(srestore_matches(conf->incexcdir[i], path))
			return 1;
	}
	return 0;
}

static int load_counters(const char *manifest, regex_t *regex, struct config *conf)
{
	return 0;
/*
	int ret=-1;
	gzFile zp=NULL;
	struct sbuf *sb;
	if(!(zp=gzopen_file(manifest, "rb")))
	{
		log_and_send("could not open manifest");
		goto end;
	}
	if(!(sb=sbuf_init()))
	{
		log_and_send_oom(__FUNCTION__);
		goto end;
	}
	else
	{
		int ars=0;
		while(1)
		{
			if((ars=sbuf_fill(NULL, zp, &sb, cntr)))
			{
				if(ars<0) goto end;
				// ars==1 means end ok
				break;
			}
			else
			{
				if((!srestore
				    || check_srestore(conf, sb.path))
				  && check_regex(regex, sb.path))
				{
					do_filecounter(p1cntr, sb.cmd, 0);
					if(sb.endfile)
					  do_filecounter_bytes(p1cntr,
                 			    strtoull(sb.endfile, NULL, 10));
				}
			}
		}
	}
	ret=0;
end:
	sbuf_free(sb);
	gzclose_fp(&zp);
	return ret;
*/
}

static int restore_remaining_dirs(struct slist *slist, struct bu *arr, int a, int i, enum action act, const char *client, char status, struct config *conf)
{
	struct sbuf *sb;
	// Restore any directories that are left in the list.
	for(sb=slist->head; sb; sb=sb->next)
	{
		if(restore_sbuf(sb, arr, a, i,
			act, client, status, conf))
				return -1;
	}
	return 0;
}

static int do_restore_manifest(const char *client, const char *datadir, struct bu *arr, int a, int i, const char *manifest, regex_t *regex, int srestore, struct config *conf, enum action act, char status, struct dpth *dpth)
{
	//int s=0;
	//size_t len=0;
	// For out-of-sequence directory restoring so that the
	// timestamps come out right:
	// FIX THIS!
//	int scount=0;
	struct slist *slist=NULL;
	int ret=-1;
	gzFile zp=NULL;
	struct sbuf *sb=NULL;
	struct blk *blk=NULL;
	int ars=0;

	// Now, do the actual restore.
	if(!(zp=gzopen_file(manifest, "rb")))
	{
		log_and_send("could not open manifest");
		goto end;
	}
	if(!(sb=sbuf_alloc())
	  || !(blk=blk_alloc())
	  || !(slist=slist_alloc())
	  || !(dpth=dpth_alloc(datadir))
	  || dpth_init(dpth))
	{
		log_and_send_oom(__FUNCTION__);
		goto end;
	}

	while(1)
	{
/* FIX THIS to allow the client to interrupt the flow for a file.
		char *buf=NULL;
		if(async_read_quick(&cmd, &buf, &len))
		{
			logp("read quick error\n");
			goto end;
		}
		if(buf)
		{
			//logp("got read quick\n");
			if(cmd==CMD_WARNING)
			{
				logp("WARNING: %s\n", buf);
				do_filecounter(conf->cntr, cmd, 0);
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
				goto end;
			}
		}
*/

		if((ars=sbuf_fill_from_gzfile(sb, zp, blk, dpth, conf)))
		{
			if(ars>0) break; // Reached the end.
			logp("In %s, error from sbuf_fill_from_gzfile()\n",
				__FUNCTION__);
			goto end; // Error;
		}

		if(blk->data)
		{
			//printf("send data: %d\n", blk->length);
			if(async_write(CMD_DATA, blk->data, blk->length))
				return -1;
			blk->data=NULL;
			continue;
		}

		if((!srestore || check_srestore(conf, sb->path))
		  && check_regex(regex, sb->path)
		  && restore_ent(client, &sb, slist,
			arr, a, i, act, status, conf))
				goto end;

		sbuf_free_contents(sb);
	}

	if(restore_remaining_dirs(slist, arr, a, i, act, client, status, conf))
		goto end;

	ret=do_restore_end(act, conf);

	print_endcounter(conf->cntr);
	print_filecounters(conf, act);

	reset_filecounters(conf, time(NULL));
	ret=0;
end:
	blk_free(blk);
	sbuf_free(sb);
	slist_free(slist);
	gzclose_fp(&zp);
	dpth_free(dpth);
	return ret;
}

// a = length of struct bu array
// i = position to restore from
static int restore_manifest(struct bu *arr, int a, int i, regex_t *regex, int srestore, enum action act, const char *client, const char *basedir, char **dir_for_notify, struct dpth *dpth, struct config *conf)
{
	int ret=-1;
	char *manifest=NULL;
	char *datadir=NULL;
//	FILE *logfp=NULL;
	char *logpath=NULL;
	char *logpathz=NULL;
	// For sending status information up to the server.
	char status=STATUS_RESTORING;

	if(act==ACTION_RESTORE) status=STATUS_RESTORING;
	else if(act==ACTION_VERIFY) status=STATUS_VERIFYING;

	if(
	    (act==ACTION_RESTORE && !(logpath=prepend_s(arr[i].path, "restorelog", strlen("restorelog"))))
	 || (act==ACTION_RESTORE && !(logpathz=prepend_s(arr[i].path, "restorelog.gz", strlen("restorelog.gz"))))
	 || (act==ACTION_VERIFY && !(logpath=prepend_s(arr[i].path, "verifylog", strlen("verifylog"))))
	 || (act==ACTION_VERIFY && !(logpathz=prepend_s(arr[i].path, "verifylog.gz", strlen("verifylog.gz"))))
	 || !(manifest=prepend_s(arr[i].path, "manifest.gz", strlen("manifest.gz")))
	 || !(datadir=prepend_s(basedir, "data", strlen("data"))))
	{
		log_and_send_oom(__FUNCTION__);
		goto end;
	}
	else if(set_logfp(logpath, conf))
	{
		char msg[256]="";
		snprintf(msg, sizeof(msg),
			"could not open log file: %s", logpath);
		log_and_send(msg);
		goto end;
	}

	*dir_for_notify=strdup(arr[i].path);

	log_restore_settings(conf, srestore);

	// First, do a pass through the manifest to set up the counters.
	if(load_counters(manifest, regex, conf)) goto end;

	if(conf->send_client_counters
	  && send_counters(client, conf))
		goto end;

	if(do_restore_manifest(client, datadir, arr, a, i, manifest, regex,
		srestore, conf, act, status, dpth)) goto end;

	ret=0;
end:
	if(!ret)
	{
		set_logfp(NULL, conf);
		compress_file(logpath, logpathz, conf);
	}
	if(manifest) free(manifest);
	if(datadir) free(datadir);
	if(logpath) free(logpath);
	if(logpathz) free(logpathz);
	return ret;
}

int do_restore_server(const char *basedir, enum action act, const char *client, int srestore, char **dir_for_notify, struct config *conf)
{
	int a=0;
	int i=0;
	int ret=0;
	int found=0;
	struct bu *arr=NULL;
	unsigned long index=0;
	regex_t *regex=NULL;
	struct dpth *dpth=NULL;

	logp("in do_restore\n");

	if(compile_regex(&regex, conf->regex)) return -1;

	if(get_current_backups(basedir, &arr, &a, 1))
	{
		if(regex) { regfree(regex); free(regex); }
		return -1;
	}

	if(!(index=strtoul(conf->backup, NULL, 10)) && a>0)
	{
		// No backup specified, do the most recent.
		ret=restore_manifest(arr, a, a-1, regex, srestore, act,
			client, basedir, dir_for_notify, dpth, conf);
		found=TRUE;
	}

	if(!found) for(i=0; i<a; i++)
	{
		if(!strcmp(arr[i].timestamp, conf->backup)
			|| arr[i].index==index)
		{
			found=TRUE;
			//logp("got: %s\n", arr[i].path);
			ret|=restore_manifest(arr, a, i, regex,
				srestore, act, client, basedir,
				dir_for_notify, dpth, conf);
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
	if(regex)
	{
		regfree(regex);
		free(regex);
	}
	return ret;
}
