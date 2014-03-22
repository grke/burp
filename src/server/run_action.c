#include "include.h"
#include "../legacy/server/run_action.c"

// FIX THIS: Somewhat haphazard.
/* Return 0 for everything OK. -1 for error, or 1 to mean that a backup is
   currently finalising. */
static int get_lock_sdirs(struct sdirs *sdirs)
{
	struct stat statp;

	// Make sure the lock directory exists.
	if(mkpath(&sdirs->lock->path, sdirs->lockdir))
	{
		async_write_str(CMD_ERROR, "problem with lock directory");
		goto error;
	}

	lock_get(sdirs->lock);
	switch(sdirs->lock->status)
	{
		case GET_LOCK_GOT: break;
		case GET_LOCK_NOT_GOT:
			logp("Another instance of client is already running.\n");
			async_write_str(CMD_ERROR,
				"another instance is already running");
			goto error;
		case GET_LOCK_ERROR:
		default:
			logp("Problem with lock file on server: %s\n",
				sdirs->lock->path);
			async_write_str(CMD_ERROR,
				"problem with lock file on server");
			goto error;
	}

	if(!lstat(sdirs->finishing, &statp))
	{
		char msg[256]="";
		logp("finalising previous backup\n");
		snprintf(msg, sizeof(msg),
			"Finalising previous backup of client. "
			"Please try again later.");
		async_write_str(CMD_ERROR, msg);
		goto finalising;
	}

	return 0;
finalising:
	return 1;
error:
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

// Used by legacy stuff.
void maybe_do_notification(int status, const char *clientdir,
	const char *storagedir, const char *filename,
	const char *brv, struct config *cconf)
{
	int a=0;
	const char *args[12];
	args[a++]=NULL; // Fill in the script name later.
	args[a++]=cconf->cname;
	args[a++]=clientdir;
	args[a++]=storagedir;
	args[a++]=filename;
	args[a++]=brv;
	if(status)
	{
		args[0]=cconf->n_failure_script;
		args[a++]="0";
		args[a++]=NULL;
		run_script(args, cconf->n_failure_arg, cconf->cntr, 1, 1);
	}
	else if((cconf->n_success_warnings_only
		&& (cconf->p1cntr->warning+cconf->cntr->warning)>0)
	  || (cconf->n_success_changes_only
		&& (cconf->cntr->total_changed>0))
	  || (!cconf->n_success_warnings_only
		&& !cconf->n_success_changes_only))
	{
		char warnings[32]="";
	// FIX THIS: conf/cntr init problem.
	//	snprintf(warnings, sizeof(warnings), "%llu",
	//		cconf->p1cntr->warning+cconf->cntr->warning);
		args[0]=cconf->n_success_script;
		args[a++]=warnings;
		args[a++]=NULL;
		run_script(args, cconf->n_success_arg,
			cconf->cntr, 1, 1);
	}
}

static int run_backup(struct sdirs *sdirs, struct config *cconf,
	struct iobuf *rbuf, const char *incexc, int *timer_ret, int resume)
{
	int ret=-1;
	char okstr[32]="";

	if(cconf->restore_client)
	{
		// This client is not the original client, so a
		// backup might cause all sorts of trouble.
		logp("Not allowing backup of %s\n", cconf->cname);
		return async_write_str(CMD_GEN, "Backup is not allowed");
	}

	// Set quality of service bits on backups.
	set_bulk_packets();

	if(!strncmp_w(rbuf->buf, "backupphase1timed"))
	{
		int a=0;
		const char *args[12];
		int checkonly=!strncmp_w(rbuf->buf, "backupphase1timedcheck");
		if(checkonly) logp("Client asked for a timer check only.\n");

		args[a++]=cconf->timer_script;
		args[a++]=cconf->cname;
		args[a++]=sdirs->current;
		args[a++]=sdirs->client;
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
			logp("Error running timer script for %s\n",
				cconf->cname);
			maybe_do_notification(ret, "",
				"error running timer script",
				"", "backup", cconf);
			return *timer_ret;
		}
		if(*timer_ret)
		{
			if(!checkonly)
				logp("Not running backup of %s\n",
					cconf->cname);
			return async_write_str(CMD_GEN,
				"timer conditions not met");
		}
		if(checkonly)
		{
			// Client was only checking the timer
			// and does not actually want to back
			// up.
			logp("Client asked for a timer check only,\n");
			logp("so a backup is not happening right now.\n");
			return async_write_str(CMD_GEN, "timer conditions met");
		}
		logp("Running backup of %s\n", cconf->cname);
	}
	else if(!cconf->client_can_force_backup)
	{
		logp("Not allowing forced backup of %s\n", cconf->cname);
		return async_write_str(CMD_GEN, "Forced backup is not allowed");
	}

	snprintf(okstr, sizeof(okstr), "ok:%d", cconf->compression);
	if(async_write_str(CMD_GEN, okstr)) return -1;
	if(cconf->protocol==PROTO_BURP1)
		ret=do_backup_server_legacy(sdirs, cconf, incexc, resume);
	else
		ret=do_backup_server(sdirs, cconf, incexc, resume);
	maybe_do_notification(ret, sdirs->client, sdirs->current,
		"log", "backup", cconf);

	return ret;
}

static int run_restore(struct sdirs *sdirs, struct config *cconf,
	struct iobuf *rbuf, int srestore)
{
	int ret=-1;
	char *cp=NULL;
	enum action act;
	char *backupnostr=NULL;
	char *restoreregex=NULL;
	char *dir_for_notify=NULL;

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
	if(conf_val_reset(backupnostr, &(cconf->backup)))
		return -1;
	if((cp=strchr(cconf->backup, ':'))) *cp='\0';

	if(act==ACTION_RESTORE)
	{
		int r;
		if((r=client_can_restore(cconf))<0)
			return -1;
		else if(!r)
		{
			logp("Not allowing restore of %s\n", cconf->cname);
			return async_write_str(CMD_GEN,
				"Client restore is not allowed");
		}
	}
	if(act==ACTION_VERIFY && !cconf->client_can_verify)
	{
		logp("Not allowing verify of %s\n", cconf->cname);
		return async_write_str(CMD_GEN, "Client verify is not allowed");
	}

	if((restoreregex=strchr(rbuf->buf, ':')))
	{
		*restoreregex='\0';
		restoreregex++;
	}
	if(conf_val_reset(restoreregex, &(cconf->regex))
	  || async_write_str(CMD_GEN, "ok"))
		return -1;
	if(cconf->protocol==PROTO_BURP1)
		ret=do_restore_server_legacy(sdirs, act,
			srestore, &dir_for_notify, cconf);
	else
		ret=do_restore_server(sdirs, act,
			srestore, &dir_for_notify, cconf);
	if(dir_for_notify)
	{
		maybe_do_notification(ret,
			sdirs->client, dir_for_notify,
			act==ACTION_RESTORE?"restorelog":"verifylog",
			act==ACTION_RESTORE?"restore":"verify",
			cconf);
		free(dir_for_notify);
	}
	return ret;
}

static int run_delete(struct sdirs *sdirs, struct config *cconf,
	struct iobuf *rbuf)
{
	char *backupno=NULL;
	if(!cconf->client_can_delete)
	{
		logp("Not allowing delete of %s\n", cconf->cname);
		async_write_str(CMD_GEN, "Client delete is not allowed");
		return -1;
	}
	backupno=rbuf->buf+strlen("delete ");
	return do_delete_server(sdirs, cconf, backupno);
}

static int run_list(struct sdirs *sdirs, struct config *cconf,
	struct iobuf *rbuf)
{
	char *backupno=NULL;
	char *browsedir=NULL;
	char *listregex=NULL;

	if(!cconf->client_can_list)
	{
		logp("Not allowing list of %s\n", cconf->cname);
		async_write_str(CMD_GEN, "Client list is not allowed");
		return -1;
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
	if(async_write_str(CMD_GEN, "ok")) return -1;

	return do_list_server(sdirs, cconf, backupno, listregex, browsedir);
}

static int unknown_command(struct iobuf *rbuf)
{
	iobuf_log_unexpected(rbuf, __FUNCTION__);
	async_write_str(CMD_ERROR, "unknown command");
	return -1;
}

int run_action_server(struct config *cconf, struct sdirs *sdirs,
	struct iobuf *rbuf, const char *incexc, int srestore, int *timer_ret)
{
	int ret;
	int resume=0;
	char msg[256]="";

	// Make sure some directories exist.
	if(mkpath(&sdirs->current, sdirs->dedup))
	{
		snprintf(msg, sizeof(msg),
			"could not mkpath %s", sdirs->current);
		log_and_send(msg);
		return -1;
	}

	if(rbuf->cmd!=CMD_GEN)
		return unknown_command(rbuf);
printf("glsd\n");
	if((ret=get_lock_sdirs(sdirs)))
	{
		// -1 on error or 1 if the backup is still finalising.
		// FIX THIS: rbuf->buf is not just 'backup' or 'list', etc.
		if(ret<0) maybe_do_notification(ret,
			"", "error in get_lock_sdirs()",
			"", rbuf->buf, cconf);
printf("glsd: %d\n", ret);
		return ret;
	}

	if(check_for_rubble_legacy(sdirs, cconf, incexc, &resume))
	{
		// FIX THIS: rbuf->buf is not just 'backup' or 'list', etc.
		maybe_do_notification(ret,
			"", "error in check_for_rubble()",
			"", rbuf->buf, cconf);
		return -1;
	}

	if(!strncmp_w(rbuf->buf, "backup"))
		return run_backup(sdirs, cconf,
			rbuf, incexc, timer_ret, resume);

	if(!strncmp_w(rbuf->buf, "restore ")
	  || !strncmp_w(rbuf->buf, "verify "))
		return run_restore(sdirs, cconf, rbuf, srestore);

	if(!strncmp_w(rbuf->buf, "delete "))
		return run_delete(sdirs, cconf, rbuf);

	if(!strncmp_w(rbuf->buf, "list ")
	  || !strncmp_w(rbuf->buf, "listb "))
		return run_list(sdirs, cconf, rbuf);

	return unknown_command(rbuf);
}
