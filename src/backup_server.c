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
#include "auth_server.h"
#include "backup_server.h"
#include "current_backups_server.h"

static int write_incexc(const char *realworking, const char *incexc)
{
	int ret=-1;
	FILE *fp=NULL;
	char *path=NULL;
	if(!(path=prepend_s(realworking, "incexc", strlen("incexc"))))
		goto end;
	if(!(fp=open_file(path, "wb")))
		goto end;
	fprintf(fp, "%s", incexc);
	ret=0;
end:
	if(close_fp(&fp))
	{
		logp("error writing to %s in write_incexc\n", path);
		ret=-1;
	}
	if(path) free(path);
	return ret;
}

static int open_log(const char *realworking, const char *client, const char *cversion, struct config *conf)
{
	char *logpath=NULL;

	if(!(logpath=prepend_s(realworking, "log", strlen("log"))))
	{
		log_and_send_oom(__FUNCTION__);
		return -1;
	}
	if(set_logfp(logpath, conf))
	{
		char msg[256]="";
		snprintf(msg, sizeof(msg),
				"could not open log file: %s", logpath);
		log_and_send(msg);
		free(logpath);
		return -1;
	}
	free(logpath);

	logp("Client version: %s\n", cversion?:"");
	// Make sure a warning appears in the backup log.
	// The client will already have been sent a message with logw.
	// This time, prevent it sending a logw to the client by specifying
	// NULL for cntr.
	if(conf->version_warn)
		version_warn(NULL, client, cversion);

	return 0;
}

static int backup_needed(struct sbuf *sb)
{
	if(sb->cmd==CMD_FILE) return 1;
	// TODO: Check previous manifest and modification time.
	return 0;
}

static void maybe_sbuf_add_to_list(struct sbuf *sb, struct slist *slist)
{
	if(backup_needed(sb))
	{
		sbuf_add_to_list(sb, slist);
		return;
	}
	// FIX THIS: now need to write the entry direct to the manifest.
}

static int deal_with_read(struct iobuf *rbuf, struct slist *slist, struct cntr *cntr, int *backup_end)
{
	int ret=0;
	static struct sbuf *snew=NULL;
	static struct sbuf *inew=NULL;

	if(!inew && !(inew=sbuf_init())) goto error;

	switch(rbuf->cmd)
	{
		case CMD_ATTRIBS_SIGS:
/*
			if(inew->path)
			{
				if(!inew->attribs) goto error;
				// New set of stuff incoming. Clean up.
				free(inew->attribs);
				free(inew->path); inew->path=NULL;
			}
			inew->attribs=*rbuf;
			inew->alen=rlen;
			inew->need_path=1;
			*rbuf=NULL;
			return 0;
*/
		case CMD_PATH_SIGS:
/*
			// Attribs should come first, so if we have not
			// already set up inew->attribs, it is an error.
			if(!inew->attribs) goto error;
			inew->path=*rbuf;
			inew->plen=rlen;
			inew->cmd=rcmd;
			inew->need_path=0;

			return 0;
*/
		case CMD_SIG:
			printf("%c:%s\n", rbuf->cmd, rbuf->buf);
			goto end;

		case CMD_ATTRIBS:
		{
			// Attribs should come first, so if we already
			// set up snew, it is an error.
			if(snew) break;
			if(!(snew=sbuf_init())) goto error;
			snew->attribs=rbuf->buf;
			snew->alen=rbuf->len;
			snew->need_path=1;
			rbuf->buf=NULL;
			return 0;
		}
		case CMD_FILE:
		case CMD_DIRECTORY:
		case CMD_SOFT_LINK:
		case CMD_HARD_LINK:
		case CMD_SPECIAL:
			// Attribs should come first, so if we have not
			// already set up snew, it is an error.
			if(!snew) goto error;
			if(snew->need_path)
			{
				snew->path=rbuf->buf;
				snew->plen=rbuf->len;
				snew->cmd=rbuf->cmd;
				snew->need_path=0;
				rbuf->buf=NULL;
			printf("got request for: %s\n", snew->path);
				if(cmd_is_link(rbuf->cmd))
				{
					snew->need_link=1;
					return 0;
				}
				else
				{
					maybe_sbuf_add_to_list(snew, slist);
					snew=NULL;
					return 0;
				}
			}
			else if(snew->need_link)
			{
				snew->linkto=rbuf->buf;
				snew->llen=rbuf->len;
				snew->need_link=0;
				rbuf->buf=NULL;
				maybe_sbuf_add_to_list(snew, slist);
				snew=NULL;
				return 0;
			}
			break;
		case CMD_WARNING:
			logp("WARNING: %s\n", rbuf);
			do_filecounter(cntr, rbuf->cmd, 0);
			goto end;
		case CMD_GEN:
			if(!strcmp(rbuf->buf, "backup_end"))
			{
				*backup_end=1;
				goto end;
			}
			break;
	}

	logp("unexpected cmd in %s, got '%c:%s'\n", __FUNCTION__, rcmd, *rbuf);
error:
	ret=-1;
	sbuf_free(inew); inew=NULL;
	sbuf_free(snew); snew=NULL;
end:
	if(rbuf->buf) { free(rbuf->buf); rbuf->buf=NULL; }
	return ret;
}

static void get_wbuf_from_sigs(struct iobuf *wbuf, struct slist *slist)
{
}

static void get_wbuf_from_files(struct iobuf *wbuf, struct slist *slist)
{
	struct sbuf *sb=slist->head;
	if(!sb) return;

	// Only need to request the path at this stage.
	if(!sb->sent_path)
	{
		wbuf->cmd=sb->cmd;
		wbuf->buf=sb->path;
		wbuf->len=sb->plen;
		sb->sent_path=1;
	}
	else
	{
		slist->head=slist->head->next;
		sbuf_free(sb);
		if(!slist->head) slist->tail=NULL;
	}
}

static int backup_server(const char *manifest, const char *client, struct cntr *p1cntr, struct cntr *cntr, struct config *conf)
{
	int ret=-1;
	gzFile mzp=NULL;
	int backup_end=0;
	struct slist *slist=NULL;
	struct iobuf *rbuf=NULL;
	struct iobuf *wbuf=NULL;

	logp("Begin backup\n");

	if(!(slist=slist_init())
	  || !(wbuf=iobuf_init())
	  || !(rbuf=iobuf_init())
	  || !(mzp=gzopen_file(manifest, comp_level(conf))))
		goto end;

	while(!backup_end)
	{
		if(!wbuf->len)
		{
			get_wbuf_from_sigs(wbuf, slist);
			if(!wbuf->len)
			{
				get_wbuf_from_files(wbuf, slist);
			}
		}

		if(wbuf->len) printf("send request: %s\n", wbuf->buf);
		if(async_rw_ng(rbuf, wbuf))
		{
			logp("error in async_rw\n");
			goto end;
		}

		if(rbuf->buf && deal_with_read(rbuf, slist, cntr, &backup_end))
			goto end;
	}
	ret=0;

end:
	if(gzclose(mzp))
	{
		logp("error closing %s in %s\n", manifest, __FUNCTION__);
		ret=-1;
	}
	logp("End backup\n");
	slist_free(slist);
	iobuf_free(rbuf);
	// Write buffer did not allocate 'buf'. 
	wbuf->buf=NULL;
	iobuf_free(wbuf);
	return ret;
}

extern int do_backup_server(const char *basedir, const char *current, const char *working, const char *currentdata, const char *finishing, struct config *cconf, const char *manifest, const char *client, const char *cversion, struct cntr *p1cntr, struct cntr *cntr, const char *incexc)
{
	int ret=0;
	char msg[256]="";
	// The timestamp file of this backup
	char *timestamp=NULL;
	// Where the new file generated from the delta temporarily goes
	char *newpath=NULL;
	// path to the last manifest
	char *cmanifest=NULL;
	// Real path to the working directory
	char *realworking=NULL;
	char tstmp[64]="";
	char *datadirtmp=NULL;
	// Path to the old incexc file.
	char *cincexc=NULL;

	struct dpth dpth;

	gzFile cmanfp=NULL;

	logp("in do_backup_server\n");

	if(!(timestamp=prepend_s(working, "timestamp", strlen("timestamp")))
	  || !(newpath=prepend_s(working, "patched.tmp", strlen("patched.tmp")))
	  || !(cmanifest=prepend_s(current, "manifest.gz", strlen("manifest.gz")))
	  || !(cincexc=prepend_s(current, "incexc", strlen("incexc")))
	  || !(datadirtmp=prepend_s(working, "data.tmp", strlen("data.tmp"))))
	{
		log_and_send_oom(__FUNCTION__);
		goto error;
	}

	if(init_dpth(&dpth, currentdata, cconf))
	{
		log_and_send("could not init_dpth\n");
		goto error;
	}

	if(get_new_timestamp(cconf, basedir, tstmp, sizeof(tstmp)))
		goto error;
	if(!(realworking=prepend_s(basedir, tstmp, strlen(tstmp))))
	{
		log_and_send_oom(__FUNCTION__);
		goto error;
	}
	// Add the working symlink before creating the directory.
	// This is because bedup checks the working symlink before
	// going into a directory. If the directory got created first,
	// bedup might go into it in the moment before the symlink
	// gets added.
	if(symlink(tstmp, working)) // relative link to the real work dir
	{
		snprintf(msg, sizeof(msg),
		  "could not point working symlink to: %s",
		  realworking);
		log_and_send(msg);
		goto error;
	}
	else if(mkdir(realworking, 0777))
	{
		snprintf(msg, sizeof(msg),
		  "could not mkdir for next backup: %s", working);
		log_and_send(msg);
		unlink(working);
		goto error;
	}
	else if(open_log(realworking, client, cversion, cconf))
	{
		goto error;
	}
	else if(mkdir(datadirtmp, 0777))
	{
		snprintf(msg, sizeof(msg),
		  "could not mkdir for datadir: %s", datadirtmp);
		log_and_send(msg);
		goto error;
	}
	else if(write_timestamp(timestamp, tstmp))
	{
		snprintf(msg, sizeof(msg),
		  "unable to write timestamp %s", timestamp);
		log_and_send(msg);
		goto error;
	}
	else if(incexc && *incexc && write_incexc(realworking, incexc))
	{
		snprintf(msg, sizeof(msg), "unable to write incexc");
		log_and_send(msg);
		goto error;
	}

	if(backup_server(manifest, client, p1cntr, cntr, cconf))
	{
		logp("error in backup\n");
		goto error;
	}

	async_write_str(CMD_GEN, "backup_end");
	logp("Backup ending - disconnect from client.\n");

	// Close the connection with the client, the rest of the job
	// we can do by ourselves.
	async_free();

	// Move the symlink to indicate that we are now finished.
	if(do_rename(working, current)) goto error;

	goto end;
error:
	ret=-1;
end:
	gzclose_fp(&cmanfp);
	if(timestamp) free(timestamp);
	if(newpath) free(newpath);
	if(cmanifest) free(cmanifest);
	if(datadirtmp) free(datadirtmp);
	if(cincexc) free(cincexc);
	set_logfp(NULL, cconf); // does an fclose on logfp.
	return ret;
}
