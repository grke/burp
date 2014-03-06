#include "include.h"
#include "../../server/backup_phase1.h"

#include <librsync.h>

static int write_incexc(const char *realworking, const char *incexc)
{
	int ret=-1;
	FILE *fp=NULL;
	char *path=NULL;
	if(!(path=prepend_s(realworking, "incexc")))
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

static int vss_opts_changed(struct sdirs *sdirs, struct config *cconf,
	const char *incexc)
{
	int ret=0;
	struct config oldconf;
	struct config newconf;
	config_init(&oldconf);
	config_init(&newconf);

	// Figure out the old config, which is in the incexc file left
	// in the current backup directory on the server.
	if(parse_incexcs_path(&oldconf, sdirs->cincexc))
	{
		// Assume that the file did not exist, and therefore
		// the old split_vss setting is 0.
		oldconf.split_vss=0;
		oldconf.strip_vss=0;
	}

	// Figure out the new config, which is either in the incexc file from
	// the client, or in the cconf on the server.
	if(incexc)
	{
		if(parse_incexcs_buf(&newconf, incexc))
		{
			// Should probably not got here.
			newconf.split_vss=0;
			newconf.strip_vss=0;
		}
	}
	else
	{
		newconf.split_vss=cconf->split_vss;
		newconf.strip_vss=cconf->strip_vss;
	}

	if(newconf.split_vss!=oldconf.split_vss)
	{
		logp("split_vss=%d (changed since last backup)\n",
			newconf.split_vss);
		ret=1;
	}
	if(newconf.strip_vss!=oldconf.strip_vss)
	{
		logp("strip_vss=%d (changed since last backup)\n",
			newconf.strip_vss);
		ret=1;
	}
	if(ret) logp("All files will be treated as new\n");
	return ret;
}

static int do_backup_server(struct sdirs *sdirs, struct config *cconf,
	const char *incexc, int resume)
{
	int ret=0;
	char msg[256]="";
	gzFile mzp=NULL;
	// Real path to the working directory
	char *realworking=NULL;
	char tstmp[64]="";

	struct dpthl dpthl;

	gzFile cmanfp=NULL;
	struct stat statp;

	logp("in do_backup_server\n");

	if(init_dpthl(&dpthl, sdirs, cconf))
	{
		log_and_send("could not init_dpthl\n");
		goto error;
	}

	if(resume)
	{
		size_t len=0;
		char real[256]="";
		if((len=readlink(sdirs->working, real, sizeof(real)-1))<0)
			len=0;
		real[len]='\0';
		if(!(realworking=prepend_s(sdirs->client, real)))
		{
			log_and_send_oom(__FUNCTION__);
			goto error;
		}
		if(open_log(realworking, cconf)) goto error;
	}
	else
	{
		// Not resuming - need to set everything up fresh.

		if(get_new_timestamp(sdirs, cconf, tstmp, sizeof(tstmp)))
			goto error;
		if(!(realworking=prepend_s(sdirs->client, tstmp)))
		{
			log_and_send_oom(__FUNCTION__);
			goto error;
		}
		// Add the working symlink before creating the directory.
		// This is because bedup checks the working symlink before
		// going into a directory. If the directory got created first,
		// bedup might go into it in the moment before the symlink
		// gets added.
		if(symlink(tstmp, sdirs->working)) // relative link to the real work dir
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
				"could not mkdir for next backup: %s",
				sdirs->working);
			log_and_send(msg);
			unlink(sdirs->working);
			goto error;
		}
		else if(open_log(realworking, cconf))
		{
			goto error;
		}
		else if(mkdir(sdirs->datadirtmp, 0777))
		{
			snprintf(msg, sizeof(msg),
			  "could not mkdir for datadir: %s", sdirs->datadirtmp);
			log_and_send(msg);
			goto error;
		}
		else if(write_timestamp(sdirs->timestamp, tstmp))
		{
			snprintf(msg, sizeof(msg),
			  "unable to write timestamp %s", sdirs->timestamp);
			log_and_send(msg);
			goto error;
		}
		else if(incexc && *incexc && write_incexc(realworking, incexc))
		{
			snprintf(msg, sizeof(msg), "unable to write incexc");
			log_and_send(msg);
			goto error;
		}

		if(backup_phase1_server(sdirs, cconf))
		{
			logp("error in phase 1\n");
			goto error;
		}
	}

	// Open the previous (current) manifest.
	// If the split_vss setting changed between the previous backup
	// and the new backup, do not open the previous manifest.
	// This will have the effect of making the client back up everything
	// fresh. Need to do this, otherwise toggling split_vss on and off
	// will result in backups that do not work.
	if(!lstat(sdirs->cmanifest, &statp)
	  && !vss_opts_changed(sdirs, cconf, incexc))
	{
		if(!(cmanfp=gzopen_file(sdirs->cmanifest, "rb")))
		{
			if(!lstat(sdirs->cmanifest, &statp))
			{
				logp("could not open old manifest %s\n",
					sdirs->cmanifest);
				goto error;
			}
		}
	}

	//if(cmanfp) logp("Current manifest: %s\n", sdirs->cmanifest);

	if(backup_phase2_server(sdirs, cconf, &cmanfp, &dpthl, resume))
	{
		logp("error in backup phase 2\n");
		goto error;
	}

	if(backup_phase3_server(sdirs, cconf,
		0 /* not recovery mode */, 1 /* compress */))
	{
		logp("error in backup phase 3\n");
		goto error;
	}

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

	// Move the symlink to indicate that we are now in the end
	// phase. 
	if(do_rename(sdirs->working, sdirs->finishing))
		goto error;
	else
	{
		set_logfp(NULL, cconf); // does an fclose on logfp.
		// finish_backup will open logfp again
		ret=backup_phase4_server(sdirs, cconf);
		if(!ret && cconf->keep>0)
			ret=remove_old_backups(sdirs, cconf);
	}

	goto end;
error:
	ret=-1;
end:
	gzclose_fp(&cmanfp);
	gzclose_fp(&mzp);
	set_logfp(NULL, cconf); // does an fclose on logfp.
	return ret;
}

static int maybe_rebuild_manifest(struct sdirs *sdirs, struct config *cconf,
	int compress)
{
	struct stat statp;
	if(!lstat(sdirs->manifest, &statp))
	{
		unlink(sdirs->phase2data);
		unlink(sdirs->unchangeddata);
		return 0;
	}
	return backup_phase3_server(sdirs, cconf,
		1 /* recovery mode */, compress);
}

static int incexc_matches(const char *fullrealwork, const char *incexc)
{
	int ret=0;
	int got=0;
	FILE *fp=NULL;
	char buf[4096]="";
	const char *inc=NULL;
	char *old_incexc_path=NULL;
	if(!(old_incexc_path=prepend_s(fullrealwork, "incexc")))
		return -1;
	if(!(fp=open_file(old_incexc_path, "rb")))
	{
		// Assume that no incexc file could be found because the client
		// was on an old version. Assume resume is OK and return 1.
		ret=1;
		goto end;
	}
	inc=incexc;
	while((got=fread(buf, 1, sizeof(buf), fp))>0)
	{
		if(strlen(inc)<(size_t)got) break;
		if(strncmp(buf, inc, got)) break;
		inc+=got;
	}
	if(inc && strlen(inc)) ret=0;
	else ret=1;
end:
	close_fp(&fp);
	free(old_incexc_path);
	return ret;
}

static int check_for_rubble(struct sdirs *sdirs, struct config *cconf,
	const char *incexc, int *resume)
{
	int ret=0;
	size_t len=0;
	char msg[256]="";
	char realwork[256]="";
	struct stat statp;
	char *logpath=NULL;
	char *fullrealwork=NULL;
	char *phase1datatmp=NULL;
	const char *wdrm=cconf->recovery_method;

	// If there is a 'finishing' symlink, we need to
	// run the finish_backup stuff.
	if(!lstat(sdirs->finishing, &statp))
	{
		logp("Found finishing symlink - attempting to complete prior backup!\n");
		ret=backup_phase4_server(sdirs, cconf);
		if(!ret) logp("Prior backup completed OK.\n");
		else log_and_send("Problem with prior backup. Please check the client log on the server.");
		goto end;
	}

	if(lstat(sdirs->working, &statp))
	{
		// No working directory - that is good.
		goto end;
	}
	if(!S_ISLNK(statp.st_mode))
	{
		log_and_send("Working directory is not a symlink.\n");
		ret=-1;
		goto end;
	}

	// The working directory has not finished being populated.
	// Check what to do.
	if((len=readlink(sdirs->working, realwork, sizeof(realwork)-1))<0)
	{
		snprintf(msg, sizeof(msg), "Could not readlink on old working directory: %s\n", strerror(errno));
		log_and_send(msg);
		ret=-1;
		goto end;
	}
	realwork[len]='\0';
	if(!(fullrealwork=prepend_s(sdirs->client, realwork)))
	{
		ret=-1;
		goto end;
	}

	if(lstat(fullrealwork, &statp))
	{
		logp("removing dangling working symlink -> %s\n", realwork);
		unlink(sdirs->working);
		goto end;
	}

	if(!(phase1datatmp=get_tmp_filename(sdirs->phase1data)))
		goto end;

	// We have found an old working directory - open the log inside
	// for appending.
	if(!(logpath=prepend_s(fullrealwork, "log")))
	{
		ret=-1;
		goto end;
	}
	if(set_logfp(logpath, cconf))
	{
		ret=-1;
		goto end;
	}

	logp("found old working directory: %s\n", fullrealwork);
	logp("working_dir_recovery_method: %s\n", wdrm);

	if(!lstat(phase1datatmp, &statp))
	{
		// Phase 1 did not complete - delete everything.
		logp("Phase 1 has not completed.\n");
		wdrm="delete";
	}

	if(!strcmp(wdrm, "delete"))
	{
		// Try to remove it and start again.
		logp("deleting old working directory\n");
		if(recursive_delete(fullrealwork,
			NULL, TRUE /* delete files */))
		{
			log_and_send("Old working directory is in the way.\n");
			ret=-1;
			goto end;
		}
		unlink(sdirs->working); // get rid of the symlink.
		goto end;
	}
	if(!strcmp(wdrm, "resume"))
	{
		if(cconf->restore_client)
		{
			// This client is not the original client, resuming	
			// might cause all sorts of trouble.
			log_and_send("Found interrupted backup - not resuming because the connected client is not the original");
			ret=-1;
			goto end;
		}

		logp("Found interrupted backup.\n");

		// Check that the current incexc configuration is the same
		// as before.
		if((ret=incexc_matches(fullrealwork, incexc))<0)
			goto end;
		if(ret)
		{
			// Attempt to resume on the next backup.
			logp("Will resume on the next backup request.\n");
			*resume=1;
			ret=0;
			goto end;
		}
		logp("Includes/excludes have changed since the last backup.\n");
		logp("Will treat last backup as finished.\n");
		wdrm="use";
	}
	if(!strcmp(wdrm, "use"))
	{
		// Use it as it is.
		logp("converting old working directory into the latest backup\n");
		free(fullrealwork); fullrealwork=NULL;

		// TODO: There might be a partial file written that is not
		// yet logged to the manifest. It does no harm other than
		// taking up some disk space. Detect this and remove it.

		// Get us a partial manifest from the files lying around.
		if(maybe_rebuild_manifest(sdirs, cconf, 1 /* compress */))
		{
			ret=-1;
			goto end;
		}

		// Now just rename the working link to be a finishing link,
		// then run this function again.
		if(do_rename(sdirs->working, sdirs->finishing))
		{
			ret=-1;
			goto end;
		}
		ret=check_for_rubble(sdirs, cconf, incexc, resume);
		goto end;
	}

	snprintf(msg, sizeof(msg),
		"Unknown working_dir_recovery_method: %s\n", wdrm);
	log_and_send(msg);
	ret=-1;

end:
	if(fullrealwork) free(fullrealwork);
	if(logpath) free(logpath);
	if(phase1datatmp) free(phase1datatmp);
	set_logfp(NULL, cconf); // fclose the logfp
	return ret;
}

/* Return 0 for everything OK. -1 for error, or 1 to mean that a backup is
   currently finalising. */
static int get_lock_and_clean(struct sdirs *sdirs, struct config *cconf,
	const char *incexc, int *resume)
{
	struct stat statp;

	// Make sure the lock directory exists.
	if(mkpath(&sdirs->lockfile, sdirs->lock))
	{
		async_write_str(CMD_ERROR, "problem with lock directory");
		return -1;
	}

	if(!get_lock(sdirs->lockfile))
	{
		sdirs->gotlock++;
		return check_for_rubble(sdirs, cconf, incexc, resume);
	}
	if(!lstat(sdirs->finishing, &statp))
	{
		char msg[256]="";
		logp("finalising previous backup\n");
		snprintf(msg, sizeof(msg),
			"Finalising previous backup of client. "
			"Please try again later.");
		async_write_str(CMD_ERROR, msg);
		return 1;
	}
	logp("another instance of client is already running,\n");
	logp("or %s is not writable.\n", sdirs->lockfile);
	async_write_str(CMD_ERROR, "another instance is already running");
	return -1;
}

static int client_can_restore(struct config *cconf)
{
	struct stat statp;
	// If there is a restore file on the server, it is always OK.
	if(cconf->restore_path
	  && !lstat(cconf->restore_path, &statp))
	{
		// Remove the file.
		unlink(cconf->restore_path);
		return 1;
	}
	return cconf->client_can_restore;
}

int run_action_server_legacy(struct config *cconf, struct sdirs *sdirs,
        struct iobuf *rbuf, const char *incexc, int srestore, int *timer_ret)
{
	int ret=0;
	char msg[256]="";

	if(rbuf->cmd==CMD_GEN && !strncmp_w(rbuf->buf, "backupphase1"))
	{
		int resume=0;

		if(cconf->restore_client)
		{
			// This client is not the original client, so a
			// backup might cause all sorts of trouble.
			logp("Not allowing backup of %s\n", cconf->cname);
			async_write_str(CMD_GEN, "Backup is not allowed");
			goto end;
		}

		// Set quality of service bits on backups.
		set_bulk_packets();
		if((ret=get_lock_and_clean(sdirs, cconf, incexc, &resume)))
		{
			// -1 on error, or 1 if the backup is still finalising.
			if(ret<0) maybe_do_notification(ret,
				"", "error in get_lock_and_clean()",
				"", "backup",
				cconf);
			goto end;
		}
		else
		{
			char okstr[32]="";
			// create basedir, without the /current part
			if(mkpath(&sdirs->current, cconf->directory))
			{
				snprintf(msg, sizeof(msg),
					"could not mkpath %s", sdirs->current);
				log_and_send(msg);
				ret=-1;
				maybe_do_notification(ret, "",
					"error creating new current directory",
					"", "backup", cconf);
				goto end;
			}
			if(!strncmp_w(rbuf->buf, "backupphase1timed"))
			{
				int a=0;
				const char *args[12];
				int checkonly=!strncmp_w(rbuf->buf,
				  "backupphase1timedcheck");
				if(checkonly)
				  logp("Client asked for a timer check only.\n");
				args[a++]=cconf->timer_script;
				args[a++]=cconf->cname;
				args[a++]=sdirs->current;
				args[a++]=cconf->directory;
				args[a++]="reserved1";
				args[a++]="reserved2";
				args[a++]=NULL;
				if((*timer_ret=run_script(args,
				  cconf->timer_arg,
				  /* cntr is NULL so that run_script does not
				     write warnings down the socket, otherwise
				     the client will never print the 'timer
				     conditions not met' message below. */
				  NULL,
				  1 /* wait */, 1 /* use logp */))<0)
				{
					ret=*timer_ret;
					logp("Error running timer script for %s\n", cconf->cname);
					maybe_do_notification(ret, "",
						"error running timer script",
						"", "backup", cconf);
					goto end;
				}
				if(*timer_ret)
				{
					if(!checkonly)
					  logp("Not running backup of %s\n",
						cconf->cname);
					async_write_str(CMD_GEN,
						"timer conditions not met");
					goto end;
				}
				if(checkonly)
				{
					// Client was only checking the timer
					// and does not actually want to back
					// up.
					ret=0;
				  	logp("Client asked for a timer check only,\n");
				  	logp("so a backup is not happening right now.\n");
					async_write_str(CMD_GEN,
						"timer conditions met");
					goto end;
				}
				
				logp("Running backup of %s\n", cconf->cname);
			}
			else if(!cconf->client_can_force_backup)
			{
				logp("Not allowing forced backup of %s\n", cconf->cname);
				async_write_str(CMD_GEN, "Forced backup is not allowed");
				goto end;
			}

			rbuf->buf=NULL;

			snprintf(okstr, sizeof(okstr), "%s:%d",
				resume?"resume":"ok", cconf->compression);
			async_write_str(CMD_GEN, okstr);
			ret=do_backup_server(sdirs, cconf, incexc, resume);
			maybe_do_notification(ret,
				sdirs->client, sdirs->current, "log", "backup",
				cconf);
		}
	}
	else if(rbuf->cmd==CMD_GEN
	  && (!strncmp_w(rbuf->buf, "restore ") || !strncmp_w(rbuf->buf, "verify ")))
	{
		char *cp=NULL;
		int resume=0; // ignored
		enum action act;
		char *backupnostr=NULL;
		// Hmm. inefficient.
	  	if(!strncmp_w(rbuf->buf, "restore "))
		{
			backupnostr=rbuf->buf+strlen("restore ");
			act=ACTION_RESTORE;
		}
		else
		{
			backupnostr=rbuf->buf+strlen("verify ");
			act=ACTION_VERIFY;
		}
		conf_val_reset(backupnostr, &(cconf->backup));
		if((cp=strchr(cconf->backup, ':'))) *cp='\0';

		if((ret=get_lock_and_clean(sdirs, cconf, incexc, &resume)))
		{
			// -1 on error, or 1 if the backup is still finalising.
			if(ret<0) maybe_do_notification(ret,
				"", "error in get_lock_and_clean()",
				"",
				act==ACTION_RESTORE?"restore":"verify",
				cconf);
		}
		else
		{
			char *restoreregex=NULL;
			char *dir_for_notify=NULL;

			if(act==ACTION_RESTORE)
			{
				int r;
				if((r=client_can_restore(cconf))<0)
				{
					ret=-1;
					goto end;
				}
				else if(!r)
				{
					logp("Not allowing restore of %s\n",
						cconf->cname);
					async_write_str(CMD_GEN,
					  "Client restore is not allowed");
					goto end;
				}
			}
			if(act==ACTION_VERIFY && !cconf->client_can_verify)
			{
				logp("Not allowing verify of %s\n", cconf->cname);
				async_write_str(CMD_GEN,
					"Client verify is not allowed");
				goto end;
			}

			if((restoreregex=strchr(rbuf->buf, ':')))
			{
				*restoreregex='\0';
				restoreregex++;
			}
			conf_val_reset(restoreregex, &(cconf->regex));
			async_write_str(CMD_GEN, "ok");
			ret=do_restore_server_legacy(sdirs,
				cconf, act, srestore, &dir_for_notify);
			if(dir_for_notify)
			{
				maybe_do_notification(ret,
					sdirs->client, dir_for_notify,
					act==ACTION_RESTORE?
						"restorelog":"verifylog",
					act==ACTION_RESTORE?
						"restore":"verify",
					cconf);
				free(dir_for_notify);
			}
		}
	}
	else if(rbuf->cmd==CMD_GEN && !strncmp_w(rbuf->buf, "delete "))
	{
		int resume=0; // ignored
		if(get_lock_and_clean(sdirs, cconf, incexc, &resume))
			ret=-1;
		else
		{
			char *backupno=NULL;
			if(!cconf->client_can_delete)
			{
				logp("Not allowing delete of %s\n", cconf->cname);
				async_write_str(CMD_GEN,
					"Client delete is not allowed");
				goto end;
			}
			backupno=rbuf->buf+strlen("delete ");
			ret=do_delete_server(sdirs, cconf, backupno);
		}
	}
	else if(rbuf->cmd==CMD_GEN
	  && (!strncmp_w(rbuf->buf, "list ")
	      || !strncmp_w(rbuf->buf, "listb ")))
	{
		int resume=0; // ignored
		if(get_lock_and_clean(sdirs, cconf, incexc, &resume))
			ret=-1;
		else
		{
			char *backupno=NULL;
			char *browsedir=NULL;
			char *listregex=NULL;

			if(!cconf->client_can_list)
			{
				logp("Not allowing list of %s\n", cconf->cname);
				async_write_str(CMD_GEN,
					"Client list is not allowed");
				goto end;
			}

			if(!strncmp_w(rbuf->buf, "list "))
			{
				if((listregex=strrchr(rbuf->buf, ':')))
				{
					*listregex='\0';
					listregex++;
				}
				backupno=rbuf->buf+strlen("list ");
			}
			else if(!strncmp_w(rbuf->buf, "listb "))
			{
				if((browsedir=strchr(rbuf->buf, ':')))
				{
					*browsedir='\0';
					browsedir++;
				}
				// strip any trailing slashes
				// (unless it is '/').
				if(strcmp(browsedir, "/")
				 && browsedir[strlen(browsedir)-1]=='/')
				  browsedir[strlen(browsedir)-1]='\0';
				backupno=rbuf->buf+strlen("listb ");
			}
			async_write_str(CMD_GEN, "ok");
			ret=do_list_server(sdirs, cconf, backupno,
				listregex, browsedir);
		}
	}
	else
	{
		iobuf_log_unexpected(rbuf, __FUNCTION__);
		async_write_str(CMD_ERROR, "unknown command");
		ret=-1;
	}

end:
	return ret;
}
