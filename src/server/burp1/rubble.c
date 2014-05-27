#include "include.h"

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

static int maybe_rebuild_manifest(struct sdirs *sdirs, struct conf *cconf,
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

int check_for_rubble_burp1(struct asfd *asfd,
	struct sdirs *sdirs, struct conf *cconf,
	const char *incexc, int *resume)
{
	int ret=0;
	ssize_t len=0;
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
		else log_and_send(asfd, "Problem with prior backup. Please check the client log on the server.");
		goto end;
	}

	if(lstat(sdirs->working, &statp))
	{
		// No working directory - that is good.
		goto end;
	}
	if(!S_ISLNK(statp.st_mode))
	{
		log_and_send(asfd, "Working directory is not a symlink.\n");
		ret=-1;
		goto end;
	}

	// The working directory has not finished being populated.
	// Check what to do.
	if((len=readlink(sdirs->working, realwork, sizeof(realwork)-1))<0)
	{
		snprintf(msg, sizeof(msg), "Could not readlink on old working directory: %s\n", strerror(errno));
		log_and_send(asfd, msg);
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
		if(recursive_delete(fullrealwork, NULL, 1 /* delete files */))
		{
			log_and_send(asfd,
				"Old working directory is in the way.\n");
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
			log_and_send(asfd, "Found interrupted backup - not resuming because the connected client is not the original");
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
		// The rename() race condition is automatically recoverable
		// here.
		if(do_rename(sdirs->working, sdirs->finishing))
		{
			ret=-1;
			goto end;
		}
		ret=check_for_rubble_burp1(asfd, sdirs, cconf, incexc, resume);
		goto end;
	}

	snprintf(msg, sizeof(msg),
		"Unknown working_dir_recovery_method: %s\n", wdrm);
	log_and_send(asfd, msg);
	ret=-1;

end:
	if(fullrealwork) free(fullrealwork);
	if(logpath) free(logpath);
	if(phase1datatmp) free(phase1datatmp);
	set_logfp(NULL, cconf); // fclose the logfp
	return ret;
}
