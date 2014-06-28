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
	free_w(&old_incexc_path);
	return ret;
}

static int maybe_rebuild_manifest(struct sdirs *sdirs, int compress,
	struct conf *cconf)
{
	struct stat statp;
	if(lstat(sdirs->manifest, &statp))
		return backup_phase3_server_burp1(sdirs,
			1 /* recovery mode */, compress, cconf);

	unlink(sdirs->phase2data);
	unlink(sdirs->unchangeddata);
	return 0;
}

static int rubble_delete(struct asfd *asfd,
	struct sdirs *sdirs, const char *fullrealwork)
{
	// Try to remove it and start again.
	logp("deleting old working directory\n");
	if(recursive_delete(fullrealwork, NULL, 1 /* delete files */))
	{
		log_and_send(asfd, "Old working directory is in the way.\n");
		return -1;
	}
	// Get rid of the symlink.
	unlink(sdirs->working);
	return 0;
}

static int rubble_use(struct asfd *asfd, struct sdirs *sdirs,
	const char *incexc, int *resume, struct conf *cconf)
{
	// Use it as it is.

	logp("converting old working directory into the latest backup\n");

	// FIX THIS: There might be a partial file written that is not yet
	// logged to the manifest. It does no harm other than taking up some
	// disk space. Detect this and remove it.

	// Get us a partial manifest from the files lying around.
	if(maybe_rebuild_manifest(sdirs, 1 /* compress */, cconf)) return -1;

	// Now just rename the working link to be a finishing link,
	// then run this function again.
	// The rename() race condition is automatically recoverable here.
	if(do_rename(sdirs->working, sdirs->finishing)) return -1;

	return check_for_rubble_burp1(asfd, sdirs, incexc, resume, cconf);
}

static int rubble_resume(struct asfd *asfd, struct sdirs *sdirs,
	const char *incexc, int *resume,
	const char *fullrealwork, struct conf *cconf)
{
	if(cconf->restore_client)
	{
		// This client is not the original client, resuming might cause
		// all sorts of trouble.
		log_and_send(asfd, "Found interrupted backup - not resuming because the connected client is not the original");
		return -1;
	}

	logp("Found interrupted backup.\n");

	// Check that the current incexc configuration is the same
	// as before.
	switch(incexc_matches(fullrealwork, incexc))
	{
		case 1:
			// Attempt to resume on the next backup.
			logp("Will resume on the next backup request.\n");
			*resume=1;
			return 0;
		case 0:
			logp("Includes/excludes changed since last backup.\n");
			logp("Will treat last backup as finished.\n");
			return rubble_use(asfd, sdirs, incexc, resume, cconf);
		case -1:
		default:
			return -1;
	}
}

static int get_fullrealwork(struct asfd *asfd,
	struct sdirs *sdirs, char **fullrealwork)
{
	ssize_t len=0;
	char msg[256]="";
	struct stat statp;
	char realwork[256]="";
	if((len=readlink(sdirs->working, realwork, sizeof(realwork)-1))<0)
	{
		snprintf(msg, sizeof(msg),
			"Could not readlink on old working directory: %s\n",
			strerror(errno));
		log_and_send(asfd, msg);
		return -1;
	}
	realwork[len]='\0';
	if(!(*fullrealwork=prepend_s(sdirs->client, realwork)))
		return -1;

	if(lstat(*fullrealwork, &statp))
	{
		logp("removing dangling working symlink -> %s\n", realwork);
		unlink(sdirs->working);
		free_w(fullrealwork);
	}
	return 0;
}

int check_for_rubble_burp1(struct asfd *asfd,
	struct sdirs *sdirs, const char *incexc,
	int *resume, struct conf *cconf)
{
	int ret=-1;
	char msg[256]="";
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
		if(backup_phase4_server_burp1(sdirs, cconf))
		{
			log_and_send(asfd, "Problem with prior backup. Please check the client log on the server.");
			goto error;
		}
		logp("Prior backup completed OK.\n");
		goto end;
	}

	if(lstat(sdirs->working, &statp)) // No working directory - good.
		goto end;
	if(!S_ISLNK(statp.st_mode))
	{
		log_and_send(asfd, "Working directory is not a symlink.\n");
		goto error;
	}

	// The working directory has not finished being populated.
	// Check what to do.
	if(get_fullrealwork(asfd, sdirs, &fullrealwork)) goto error;
	if(!fullrealwork) goto end;

	// We have found an old working directory - open the log inside
	// for appending.
	if(!(logpath=prepend_s(fullrealwork, "log"))
	  || set_logfp(logpath, cconf))
		goto error;

	logp("found old working directory: %s\n", fullrealwork);
	logp("working_dir_recovery_method: %s\n", wdrm);

	if(!(phase1datatmp=get_tmp_filename(sdirs->phase1data)))
		goto error;
	if(!lstat(phase1datatmp, &statp))
	{
		// Phase 1 did not complete - delete everything.
		logp("Phase 1 has not completed.\n");
		wdrm="delete";
	}

	if(!strcmp(wdrm, "delete"))
	{
		if(rubble_delete(asfd, sdirs, fullrealwork))
			goto error;
	}
	else if(!strcmp(wdrm, "use"))
	{
		if(rubble_use(asfd, sdirs, incexc, resume, cconf))
			goto error;
	}
	else if(!strcmp(wdrm, "resume"))
	{
		if(rubble_resume(asfd,
		  sdirs, incexc, resume, fullrealwork, cconf))
			goto error;
	}
	else
	{
		snprintf(msg, sizeof(msg),
			"Unknown working_dir_recovery_method: %s\n", wdrm);
		log_and_send(asfd, msg);
		goto error;
	}

end:
	ret=0;
error:
	free_w(&fullrealwork);
	free_w(&logpath);
	free_w(&phase1datatmp);
	set_logfp(NULL, cconf); // fclose the logfp
	return ret;
}
