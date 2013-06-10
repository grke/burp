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
	FILE *logfp=NULL;
	char *logpath=NULL;

	if(!(logpath=prepend_s(realworking, "log", strlen("log"))))
	{
		log_and_send_oom(__FUNCTION__);
		return -1;
	}
	if(!(logfp=open_file(logpath, "ab")) || set_logfp(logfp, conf))
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

static int backup_server(const char *phase1data, const char *client, struct cntr *p1cntr, struct cntr *cntr, struct config *conf)
{
	int ars=0;
	int ret=0;
	int quit=0;
	struct sbuf sb;
	gzFile p1zp=NULL;
	char *phase1tmp=NULL;

	logp("Begin phase1 (file system scan)\n");

	if(!(phase1tmp=get_tmp_filename(phase1data)))
		return -1;

	if(!(p1zp=gzopen_file(phase1tmp, comp_level(conf))))
	{
		free(phase1tmp);
		return -1;
	}

	init_sbuf(&sb);
	while(!quit)
	{
		free_sbuf(&sb);
		if((ars=sbuf_fill(NULL, NULL, &sb, p1cntr)))
		{
			if(ars<0) ret=-1;
			//ars==1 means it ended ok.
			// Last thing the client sends is 'backupphase2', and
			// it wants an 'ok' reply.
			if(async_write_str(CMD_GEN, "ok")
			  || send_msg_zp(p1zp, CMD_GEN,
				"phase1end", strlen("phase1end")))
					ret=-1;
			break;
		}
		write_status(client, STATUS_SCANNING, sb.path, p1cntr, cntr);
		if(sbuf_to_manifest_phase1(&sb, NULL, p1zp))
		{
			ret=-1;
			break;
		}
		do_filecounter(p1cntr, sb.cmd, 0);

		if(sb.cmd==CMD_FILE
		  || sb.cmd==CMD_ENC_FILE
		  || sb.cmd==CMD_METADATA
		  || sb.cmd==CMD_ENC_METADATA
		  || sb.cmd==CMD_EFS_FILE)
			do_filecounter_bytes(p1cntr,
				(unsigned long long)sb.statp.st_size);
	}

	free_sbuf(&sb);
        if(gzclose(p1zp))
	{
		logp("error closing %s in backup_phase1_server\n", phase1tmp);
		ret=-1;
	}
	if(!ret && do_rename(phase1tmp, phase1data))
		ret=-1;
	free(phase1tmp);

	//print_filecounters(p1cntr, cntr, ACTION_BACKUP);

	logp("End phase1 (file system scan)\n");

	return ret;
}

extern int do_backup_server(const char *basedir, const char *current, const char *working, const char *currentdata, const char *finishing, struct config *cconf, const char *manifest, const char *phase1data, const char *phase2data, const char *unchangeddata, const char *client, const char *cversion, struct cntr *p1cntr, struct cntr *cntr, const char *incexc)
{
	int ret=0;
	char msg[256]="";
	gzFile mzp=NULL;
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
	struct stat statp;

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

	if(backup_server(phase1data, client, p1cntr, cntr, cconf))
	{
		logp("error in backup\n");
		goto error;
	}

	//if(cmanfp) logp("Current manifest: %s\n", cmanifest);

	// will not write anything more to
	// the new manifest
	// finish_backup will open it again
	// for reading
	if(gzclose_fp(&mzp))
	{
		logp("Error closing manifest after phase3\n");
		goto error;
	}

	async_write_str(CMD_GEN, "okbackupend");
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
	gzclose_fp(&mzp);
	if(timestamp) free(timestamp);
	if(newpath) free(newpath);
	if(cmanifest) free(cmanifest);
	if(datadirtmp) free(datadirtmp);
	if(cincexc) free(cincexc);
	set_logfp(NULL, cconf); // does an fclose on logfp.
	return ret;
}
