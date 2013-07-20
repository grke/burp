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

static int add_to_slist(struct sbuf **shead, struct sbuf **stail, char cmd, char *buf, size_t len, int *scan_end, struct cntr *cntr)
{
	if(cmd==CMD_ATTRIBS)
	{
		struct sbuf *sb;
		if(!(sb=sbuf_init())) return -1;
//		if(sbuf_fill_ng(sb, buf, len)) return -1;
		if(*stail)
		{
			// Add to the end of the list.
			(*stail)->next=sb;
			(*stail)=sb;
		}
		else
		{
			// Start the list.
			*shead=sb;
			*stail=sb;
		}
		return 0;
	}
	else if(cmd==CMD_ATTRIBS_BLKS)
	{
		struct sbuf *sb;
		if(!(sb=sbuf_init())) return -1;
//		if(sbuf_fill_ng(sb, buf, len)) return -1;
		printf("receiving blocks for %s\n", sb->path);
		sbuf_free(sb);
		return 0;
	}
	else if(cmd==CMD_WARNING)
	{
		logp("WARNING: %s\n", buf);
		do_filecounter(cntr, cmd, 0);
		if(buf) { free(buf); buf=NULL; }
		return 0;
	}
	else if(cmd==CMD_GEN)
	{
		if(!strcmp(buf, "scan_end"))
		{
			*scan_end=1;
			return 0;
		}
	}

	logp("unexpected cmd in %s, got '%c'\n",
		__FUNCTION__, cmd);
	if(buf) { free(buf); buf=NULL; }
	return -1;
}

static int backup_needed(struct sbuf *sb)
{
	if(sb->cmd==CMD_FILE) return 1;
	// TODO: Check previous manifest and modification time.
	return 0;
}

static int backup_server(const char *manifest, const char *client, struct cntr *p1cntr, struct cntr *cntr, struct config *conf)
{
	int ret=0;
	int scan_end=0;
	gzFile mzp=NULL;
	struct sbuf *shead=NULL;
	struct sbuf *stail=NULL;

	logp("Begin backup\n");

	if(!(mzp=gzopen_file(manifest, comp_level(conf))))
		return -1;

	while(1)
	{
		struct sbuf *sb;
		for(sb=shead; sb; sb=sb->next)
		{
			char rcmd;
			char *rbuf=NULL;
			size_t rlen=0;
		//	printf("process: %s\n", sb->path);

			if(!backup_needed(sb))
			{
				// Write to manifest here.

				if(!(shead=sb->next)) stail=NULL;
				// TODO: Make free_sbuf() free the pointer as
				// well.
				sbuf_free(sb);
				continue;
			}

	//	printf("request: %s\n", sb->path);
			if(async_write(CMD_ATTRIBS, sb->attribs, sb->alen)
			// May also read.
			  || async_rw_ensure_write(&rcmd, &rbuf, &rlen,
				sb->cmd, sb->path, sb->plen))
			{
				logp("error in async_rw\n");
				return -1;
			}

			if(!scan_end)
			{
				if(rbuf)
				{
					if(add_to_slist(&shead, &stail,
						rcmd, rbuf, rlen,
						&scan_end, cntr))
					{
						ret=-1;
						break;
					}
			//		printf("opportune: %s\n", stail->path);
				}
			}

			if(!(shead=sb->next)) stail=NULL;
			// TODO: Make free_sbuf() free the pointer as well.
			sbuf_free(sb);
			break;
		}

		if(!shead)
		{
			if(scan_end)
			{
				if(async_write_str(CMD_GEN, "backup_end"))
					ret=-1;
				break;
			}
			else
			{
				// Nothing to do.
				// Maybe the client is sending more file names.
				char rcmd;
				char *rbuf=NULL;
				size_t rlen=0;
				if(async_read(&rcmd, &rbuf, &rlen))
				{
					logp("error in async_read\n");
					return -1;
				}
				if(add_to_slist(&shead, &stail,
					rcmd, rbuf, rlen,
					&scan_end, cntr))
				{
					ret=-1;
					break;
				}
			}
		}
	}

        if(gzclose(mzp))
	{
		logp("error closing %s in %s\n", manifest, __FUNCTION__);
		ret=-1;
	}

	logp("End backup\n");

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
