#include "../burp.h"
#include "../alloc.h"
#include "../asfd.h"
#include "../async.h"
#include "../fsops.h"
#include "../fzp.h"
#include "../handy.h"
#include "../lock.h"
#include "../log.h"
#include "../prepend.h"
#include "backup_phase4.h"
#include "compress.h"
#include "rubble.h"
#include "run_action.h"
#include "sdirs.h"
#include "timestamp.h"
#include "zlibio.h"

static char *get_resume_path(const char *path)
{
	return prepend_s(path, "resumed");
}

static int append_to_resume_file(const char *path)
{
	int ret=-1;
	char tstmp[48]="";
	char *resume_path=NULL;

	if(timestamp_get_new(/*index*/0,
		tstmp, sizeof(tstmp),
		/*bufforfile*/NULL, /*bs*/0,
		/*format*/NULL))
			goto end;
	if(!(resume_path=get_resume_path(path)))
		goto end;
	ret=timestamp_write(resume_path, tstmp);
end:
	free_w(&resume_path);
	return ret;
}

static int resume_count(const char *path)
{
	int count=-1;
	char buf[256]="";
	struct fzp *fzp=NULL;
	char *resume_path=NULL;

	if(!(resume_path=get_resume_path(path)))
		goto end;
	if(!(fzp=fzp_open(resume_path, "rb")))
		goto end;
	count=0;
	while(fzp_gets(fzp, buf, sizeof(buf)))
		count++;
end:
	fzp_close(&fzp);
	free_w(&resume_path);
	return count;
}

static int incexc_matches(const char *fullrealwork, const char *incexc)
{
	int ret=0;
	int got=0;
	struct fzp *fzp=NULL;
	char buf[4096]="";
	const char *inc=NULL;
	char *old_incexc_path=NULL;
	if(!(old_incexc_path=prepend_s(fullrealwork, "incexc")))
		return -1;
	if(!(fzp=fzp_open(old_incexc_path, "rb")))
	{
		// Assume that no incexc file could be found because the client
		// was on an old version. Assume resume is OK and return 1.
		ret=1;
		goto end;
	}
	inc=incexc;
	while((got=fzp_read(fzp, buf, sizeof(buf)))>0)
	{
		if(strlen(inc)<(size_t)got) break;
		if(strncmp(buf, inc, got)) break;
		inc+=got;
	}
	if(inc && strlen(inc)) ret=0;
	else ret=1;
end:
	fzp_close(&fzp);
	free_w(&old_incexc_path);
	return ret;
}

static int working_delete(
	struct async *as,
	struct sdirs *sdirs,
	struct conf **cconfs
) {
	// Try to remove it and start again.
	logp("deleting old working directory\n");

	if(get_int(cconfs[OPT_N_FAILURE_BACKUP_WORKING_DELETION]))
	{
		// The status needs to be non-zero in order to send a failure
		// notification.
		int status=1;

		// Need to do notify before actually deleting, so that it grabs
		// the not-yet deleted log. Close the log file pointer first.
		log_fzp_set(NULL, cconfs);

		maybe_do_notification(as->asfd, status,
			sdirs->client, sdirs->current,
			"log", "backup", cconfs);
	}

	if(recursive_delete(sdirs->rworking))
	{
		log_and_send(as->asfd,
			"Old working directory is in the way.\n");
		return -1;
	}
	// Get rid of the symlink.
	unlink(sdirs->working);
	return 0;
}

static int working_resume(struct async *as, struct sdirs *sdirs,
	const char *incexc, int *resume, struct conf **cconfs)
{
	if(get_string(cconfs[OPT_SUPER_CLIENT]))
	{
		// This client is not the original client, resuming might cause
		// all sorts of trouble.
		log_and_send(as->asfd, "Found interrupted backup - not resuming because the connected client is not the original");
		return -1;
	}

	logp("Found interrupted backup.\n");

	// Check that the current incexc configuration is the same
	// as before.
	switch(incexc_matches(sdirs->rworking, incexc))
	{
		case 1:
			// Attempt to resume on the next backup.
			logp("Will resume on the next backup request.\n");
			*resume=1;
			return 0;
		case 0:
			logp("Includes/excludes changed since last backup.\n");
			logp("Will delete instead of resuming.\n");
			return working_delete(as, sdirs, cconfs);
		case -1:
		default:
			return -1;
	}
}

static int get_fullrealwork(struct sdirs *sdirs)
{
	struct stat statp;

	if(sdirs_get_real_working_from_symlink(sdirs))
		return -1;

	if(lstat(sdirs->rworking, &statp))
	{
		logp("removing dangling working symlink %s -> %s\n",
			sdirs->working, sdirs->rworking);
		unlink(sdirs->working);
		free_w(&sdirs->rworking);
	}
	return 0;
}

static int do_unlink(const char *path)
{
	if(unlink(path))
	{
		logp("Could not unlink '%s': %s", path, strerror(errno));
		return -1;
	}
	return 0;
}

static int fix_log_finishing(struct sdirs *sdirs, struct conf **cconfs)
{
	int ret=-1;
	char *path_log=NULL;
	char *path_log_gz=NULL;
	char *path_log_tmp=NULL;

	if(!(path_log=prepend_s(sdirs->finishing, "log"))
	  || !(path_log_gz=prepend_s(sdirs->finishing, "log.gz"))
	  || !(path_log_tmp=prepend_s(sdirs->finishing, "log.tmp")))
		goto end;

	if(is_reg_lstat(path_log)==1)
	{
		if(is_reg_lstat(path_log_gz)==1)
		{
			// If this has happened, either file should be good to
			// use. Delete the compressed one, as we will keep
			// logging to the uncompressed one.
			do_unlink(path_log_gz);
			goto end;
		}
		else
		{
			// Everything is OK.
			ret=0;
		}
	}
	else
	{
		if(is_reg_lstat(path_log_gz)==1)
		{
			// Need to inflate so that we can log to it again,
			// and compress it later.
			if(zlib_inflate(/*asfd*/NULL, path_log_gz,
				path_log_tmp, get_cntr(cconfs)))
					goto end;
			if(do_rename(path_log_tmp, path_log))
				goto end;
			do_unlink(path_log_gz);
			goto end;
		}
		else
		{
			logp("Neither %s nor %s exist. That is odd!",
				path_log, path_log_gz);
			ret=0;
		}
	}
end:
	if(!ret)
	{
		// Should be OK to re-open the log file now.
		if(log_fzp_set(path_log, cconfs))
			ret=-1;
	}

	free_w(&path_log);
	free_w(&path_log_gz);
	free_w(&path_log_tmp);
	return ret;
}

static int recover_finishing(struct async *as,
	struct sdirs *sdirs, struct conf **cconfs)
{
	char msg[128]="";
	struct asfd *asfd=as->asfd;

	if(fix_log_finishing(sdirs, cconfs))
		return -1;

	logp("Found finishing symlink - attempting to complete prior backup!\n");

	if(append_to_resume_file(sdirs->finishing))
		return -1;

	snprintf(msg, sizeof(msg),
		"Now finalising previous backup of client. "
		"Please try again later.");
	asfd->write_str(asfd, CMD_ERROR, msg);

	// Need to check whether the log has been compressed. If it hasn't,
	// we need to inflate it again.

	// Do not need the client connected any more.
	// Disconnect.
	logp("Disconnect from client.\n");
	as->asfd_remove(as, asfd);
	asfd_close(asfd);

	if(backup_phase4_server_all(sdirs, cconfs))
	{
		logp("Problem with prior backup. Please check the client log on the server.");
		return -1;
	}

	logp("Prior backup completed OK\n");
        log_fzp_set(NULL, cconfs);
	compress_filename(sdirs->finishing,
		"log", "log.gz", get_int(cconfs[OPT_COMPRESSION]));

	// backup_stats?!


	// Move the symlink to indicate that we are now in the end
	// phase.
	// FIX THIS: Check whether the rename race condition is recoverable
	// here.
	if(do_rename(sdirs->finishing, sdirs->current)) return -1;
	return 0;
}

static void log_recovery_method(struct sdirs *sdirs,
	enum recovery_method recovery_method)
{
	logp("found old working directory: %s\n", sdirs->rworking);
	logp("working_dir_recovery_method: %s\n",
		recovery_method_to_str(recovery_method));
}

static int recover_working(struct async *as,
	struct sdirs *sdirs, const char *incexc,
	int *resume, struct conf **cconfs)
{
	int ret=-1;
	char msg[256]="";
	char *logpath=NULL;
	struct stat statp;
	char *phase1datatmp=NULL;
	int resume_attempts=0;
	int max_resume_attempts=get_int(cconfs[OPT_MAX_RESUME_ATTEMPTS]);
	enum recovery_method recovery_method=get_e_recovery_method(
		cconfs[OPT_WORKING_DIR_RECOVERY_METHOD]);

	// The working directory has not finished being populated.
	// Check what to do.
	if(get_fullrealwork(sdirs)) goto end;
	if(!sdirs->rworking) goto end;

	log_recovery_method(sdirs, recovery_method);

	if(!(phase1datatmp=get_tmp_filename(sdirs->phase1data)))
		goto end;
	// If there is still a phase1 tmp file...
	if(!lstat(phase1datatmp, &statp)
	  ||
		// ...or phase1 has not even got underway yet...
		(lstat(phase1datatmp, &statp)
		  && lstat(sdirs->phase1data, &statp)
		  && lstat(sdirs->changed, &statp)
		  && lstat(sdirs->unchanged, &statp)))
	{
		// ...phase 1 did not complete - delete everything.
		logp("Phase 1 has not completed.\n");
		recovery_method=RECOVERY_METHOD_DELETE;
	}
	else
	{
		append_to_resume_file(sdirs->working);

		if(max_resume_attempts>0)
		{
			logp("max_resume_attempts: %d\n", max_resume_attempts);
			if((resume_attempts=resume_count(sdirs->working))<0)
				goto end;
			if(resume_attempts > max_resume_attempts)
			{
				logp("no resume attempts remaining, will delete\n");
				recovery_method=RECOVERY_METHOD_DELETE;
			}
			else
			{
				logp("resume attempts: %d\n", resume_attempts);
				logp("remaining resume attempts: %d\n",
					max_resume_attempts - resume_attempts);
			}
		}
	}

	if(recovery_method==RECOVERY_METHOD_DELETE)
	{
		ret=working_delete(as, sdirs, cconfs);
		goto end;
	}

	// We are not deleting the old working directory - open the log inside
	// for appending.
	if(!(logpath=prepend_s(sdirs->rworking, "log"))
	  || log_fzp_set(logpath, cconfs))
		goto end;

	switch(recovery_method)
	{
		case RECOVERY_METHOD_DELETE:
			// Dealt with above.
			break;
		case RECOVERY_METHOD_RESUME:
			ret=working_resume(as, sdirs, incexc, resume, cconfs);
			break;
		case RECOVERY_METHOD_UNSET:
		default:
			snprintf(msg, sizeof(msg),
				"Unknown working_dir_recovery_method: %d\n",
					(int)recovery_method);
			log_and_send(as->asfd, msg);
			break;
	}

end:
	free_w(&logpath);
	free_w(&phase1datatmp);
	log_fzp_set(NULL, cconfs); // fclose the logfzp
	return ret;
}

static int recover_currenttmp(struct sdirs *sdirs)
{
	logp("Found currenttmp symlink\n");
	switch(is_lnk_valid(sdirs->currenttmp))
	{
		case 0:
			logp("But currenttmp is not pointing at something valid.\n");
			logp("Deleting it.\n");
			if(append_to_resume_file(sdirs->currenttmp))
				return -1;
			return unlink_w(sdirs->currenttmp, __func__);
		case -1:
			return -1;
	}

	switch(is_lnk_lstat(sdirs->current))
	{
		case 0:
			logp("But current already exists and is not a symlink!\n");
			logp("Giving up.\n");
			return -1;
		case 1:
			logp("But current symlink already exists!\n");
			switch(is_lnk_valid(sdirs->current))
			{
				case 0:
					logp("But current symlink is not pointing at something valid.\n");
					logp("Replacing current with currenttmp.\n");
					if(append_to_resume_file(
						sdirs->currenttmp))
							return -1;
					return do_rename(sdirs->currenttmp,
						sdirs->current);
				case 1:
					logp("And current symlink points at something valid.\n");
					logp("Deleting currenttmp.\n");
					return unlink_w(sdirs->currenttmp, __func__);
				default:
					return -1;
			}
		default:
			logp("Renaming currenttmp to current\n");
			if(append_to_resume_file(sdirs->currenttmp))
				return -1;
			return do_rename(sdirs->currenttmp, sdirs->current);
	}
}

int check_for_rubble(struct sdirs *sdirs)
{
	return is_lnk_lstat(sdirs->finishing)>0
	  || is_lnk_lstat(sdirs->working)>0
	  || is_lnk_lstat(sdirs->currenttmp)>0;
}

// Return 1 if the backup is now finalising.
int check_for_rubble_and_clean(struct async *as,
	struct sdirs *sdirs, const char *incexc,
	int *resume, struct conf **cconfs)
{
	struct asfd *asfd=as->asfd;

	switch(is_lnk_lstat(sdirs->finishing))
	{
		case 1:
			if(recover_finishing(as, sdirs, cconfs))
				return -1;
			return 1;
		case 0:
			log_and_send(asfd,
				"Finishing directory is not a symlink.\n");
			return -1;
	}

	switch(is_lnk_lstat(sdirs->working))
	{
		case 1:
			return recover_working(as,
				sdirs, incexc, resume, cconfs);
		case 0:
			log_and_send(asfd,
				"Working directory is not a symlink.\n");
			return -1;
	}

	switch(is_lnk_lstat(sdirs->currenttmp))
	{
		case 1:
			return recover_currenttmp(sdirs);
		case 0:
			log_and_send(asfd,
				"Currenttmp directory is not a symlink.\n");
			return -1;
	}

	return 0;
}
