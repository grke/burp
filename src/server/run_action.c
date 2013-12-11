#include "include.h"

/*
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
*/

static int get_lock_sdirs(struct sdirs *sdirs)
{
	// Make sure the lock directory exists.
printf("before: %s %s\n", sdirs->lockfile, sdirs->lock);
	if(mkpath(&sdirs->lockfile, sdirs->lock))
	{
		async_write_str(CMD_ERROR, "problem with lock directory");
		return -1;
	}

	if(!get_lock(sdirs->lockfile))
	{
		sdirs->gotlock++;
		return 0;
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
		args[0]=cconf->notify_failure_script;
		args[a++]="0";
		args[a++]=NULL;
		run_script(args, cconf->notify_failure_arg, cconf->nfcount,
			cconf->cntr, 1, 1);
	}
	else if((cconf->notify_success_warnings_only
		&& (cconf->p1cntr->warning+cconf->cntr->warning)>0)
	  || (cconf->notify_success_changes_only
		&& (cconf->cntr->total_changed>0))
	  || (!cconf->notify_success_warnings_only
		&& !cconf->notify_success_changes_only))
	{
		char warnings[32]="";
	// FIX THIS: conf/cntr init problem.
	//	snprintf(warnings, sizeof(warnings), "%llu",
	//		cconf->p1cntr->warning+cconf->cntr->warning);
		args[0]=cconf->notify_success_script;
		args[a++]=warnings;
		args[a++]=NULL;
		run_script(args, cconf->notify_success_arg, cconf->nscount,
			cconf->cntr, 1, 1);
	}
}

static int run_backup(struct sdirs *sdirs, struct config *cconf,
	struct iobuf *rbuf, const char *incexc, int *timer_ret)
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

	if(get_lock_sdirs(sdirs)) return -1;

	if(!strcmp(rbuf->buf, "backup_timed"))
	{
		int a=0;
		const char *args[12];
		args[a++]=cconf->timer_script;
		args[a++]=cconf->cname;
		args[a++]=sdirs->current;
		args[a++]=sdirs->client;
		args[a++]="reserved1";
		args[a++]="reserved2";
		args[a++]=NULL;
		if((*timer_ret=run_script(args,
		  cconf->timer_arg,
		  cconf->tacount,
		  /* cntr is NULL so that run_script does not
		     write warnings down the socket, otherwise
		     the client will never print the 'timer
		     conditions not met' message below. */
		  NULL,
		  1 /* wait */, 1 /* use logp */))<0)
		{
			logp("Error running timer script for %s\n",
				cconf->cname);
			return *timer_ret;
		}
		if(*timer_ret)
		{
			logp("Not running backup of %s\n", cconf->cname);
			return async_write_str(CMD_GEN,
				"timer conditions not met");
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
	ret=do_backup_server(sdirs, cconf, incexc);
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

	if(get_lock_sdirs(sdirs)) return -1;

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
	if(get_lock_sdirs(sdirs)) return -1;
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

	if(get_lock_sdirs(sdirs)) return -1;

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

static void unknown_command(struct iobuf *rbuf)
{
	iobuf_log_unexpected(rbuf, __FUNCTION__);
	async_write_str(CMD_ERROR, "unknown command");
}

int run_action(struct config *cconf, struct sdirs *sdirs, struct iobuf *rbuf,
	const char *incexc, int srestore, int *timer_ret)
{
	int ret=-1;
	char msg[256]="";

	// Make sure some directories exist.
	if(mkpath(&sdirs->current, sdirs->dedup))
	{
		snprintf(msg, sizeof(msg),
			"could not mkpath %s", sdirs->current);
		log_and_send(msg);
	}
	else if(rbuf->cmd!=CMD_GEN)
		unknown_command(rbuf);
	else if(!strncmp_w(rbuf->buf, "backup"))
		ret=run_backup(sdirs, cconf, rbuf, incexc, timer_ret);
	else if(!strncmp_w(rbuf->buf, "restore ")
	  || !strncmp_w(rbuf->buf, "verify "))
		ret=run_restore(sdirs, cconf, rbuf, srestore);
	else if(!strncmp_w(rbuf->buf, "delete "))
		ret=run_delete(sdirs, cconf, rbuf);
	else if(!strncmp_w(rbuf->buf, "list ")
	  || !strncmp_w(rbuf->buf, "listb "))
		ret=run_list(sdirs, cconf, rbuf);
	else
		unknown_command(rbuf);

	return ret;
}
