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

static void maybe_sbuf_add_to_list(struct sbuf *sb, struct sbuf **shead, struct sbuf **stail)
{
	if(backup_needed(sb))
	{
		sbuf_add_to_list(sb, shead, stail);
		return;
	}
	// FIX THIS: now need to write the entry direct to the manifest.
}

static int deal_with_read(char rcmd, char **rbuf, size_t rlen, struct sbuf **shead, struct sbuf **stail, struct cntr *cntr, int *backup_end)
{
	int ret=0;
	static struct sbuf *snew=NULL;
	switch(rcmd)
	{
		case CMD_ATTRIBS:
		{
			if(snew)
			{
				// Attribs should come first, so if we already
				// set up snew, it is an error.
				sbuf_free(snew); snew=NULL;
				break;
			}
			if(!(snew=sbuf_init())) goto error;
			snew->attribs=*rbuf;
			snew->alen=rlen;
			snew->need_path=1;
			*rbuf=NULL;
			return 0;
		}
		case CMD_FILE:
		case CMD_DIRECTORY:
		case CMD_SOFT_LINK:
		case CMD_HARD_LINK:
		case CMD_SPECIAL:
			if(!snew)
			{
				// Attribs should come first, so if we have not
				// already set up snew, it is an error.
				break;
			}
			if(snew->need_path)
			{
				snew->path=*rbuf;
				snew->plen=rlen;
				snew->cmd=rcmd;
				snew->need_path=0;
				*rbuf=NULL;
			printf("got request for: %s\n", snew->path);
				if(cmd_is_link(rcmd))
				{
					snew->need_link=1;
					return 0;
				}
				else
				{
					maybe_sbuf_add_to_list(snew,
						shead, stail);
					snew=NULL;
					return 0;
				}
			}
			else if(snew->need_link)
			{
				snew->linkto=*rbuf;
				snew->llen=rlen;
				snew->need_link=0;
				*rbuf=NULL;
				maybe_sbuf_add_to_list(snew, shead, stail);
				snew=NULL;
				return 0;
			}
			break;
		case CMD_WARNING:
			logp("WARNING: %s\n", rbuf);
			do_filecounter(cntr, rcmd, 0);
			goto end;
		case CMD_GEN:
			if(!strcmp(*rbuf, "backup_end"))
			{
				*backup_end=1;
				goto end;
			}
			break;
	}

	logp("unexpected cmd in %s, got '%c:%s'\n", __FUNCTION__, rcmd, *rbuf);
error:
	ret=-1;
end:
	if(*rbuf) { free(*rbuf); *rbuf=NULL; }
	return ret;
}

static void get_wbuf_from_sigs(char *wcmd, char **wbuf, size_t *wlen, struct sbuf **shead, struct sbuf **stail)
{
}

static void get_wbuf_from_files(char *wcmd, char **wbuf, size_t *wlen, struct sbuf **shead, struct sbuf **stail)
{
	struct sbuf *sb=*shead;
	if(!sb) return;

	// Only need to request the path at this stage.
	if(!sb->sent_path)
	{
		*wcmd=sb->cmd;
		*wbuf=sb->path;
		*wlen=sb->plen;
		sb->sent_path=1;
	}
	else
	{
		*shead=(*shead)->next;
		sbuf_free(sb);
		if(!*shead) *stail=NULL;
	}
}

static int backup_server(const char *manifest, const char *client, struct cntr *p1cntr, struct cntr *cntr, struct config *conf)
{
	int ret=0;
	gzFile mzp=NULL;
	struct sbuf *shead=NULL;
	struct sbuf *stail=NULL;
	char rcmd=CMD_ERROR;
	char *rbuf=NULL;
	size_t rlen=0;
	char wcmd=CMD_ERROR;
	char *wbuf=NULL;
	size_t wlen=0;
	int backup_end=0;

	logp("Begin backup\n");

	if(!(mzp=gzopen_file(manifest, comp_level(conf))))
		return -1;

	while(!backup_end)
	{
		if(!wlen)
		{
			get_wbuf_from_sigs(&wcmd, &wbuf, &wlen,
				&shead, &stail);
			if(!wlen)
			{
				get_wbuf_from_files(&wcmd, &wbuf, &wlen,
					&shead, &stail);
			}
		}

		if(wlen) printf("send request: %s\n", wbuf);
		if(async_rw(&rcmd, &rbuf, &rlen, wcmd, wbuf, &wlen))
		{
			logp("error in async_rw\n");
			goto end;
		}

		if(rbuf && deal_with_read(rcmd, &rbuf, rlen,
			&shead, &stail, cntr, &backup_end))
				goto end;
	}

	if(gzclose(mzp))
	{
		logp("error closing %s in %s\n", manifest, __FUNCTION__);
		ret=-1;
	}

end:
	logp("End backup\n");
	sbuf_free_list(shead); shead=NULL;
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
