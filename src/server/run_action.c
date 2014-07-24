#include "include.h"
#include "burp1/rubble.h"
#include "burp2/restore.h"
#include "burp2/rubble.h"

// FIX THIS: Somewhat haphazard.
/* Return 0 for everything OK. -1 for error, or 1 to mean that a backup is
   currently finalising. */
static int get_lock_sdirs(struct asfd *asfd, struct sdirs *sdirs)
{
	struct stat statp;

	// Make sure the lock directory exists.
	if(mkpath(&sdirs->lock->path, sdirs->lockdir))
	{
		asfd->write_str(asfd, CMD_ERROR, "problem with lock directory");
		goto error;
	}

	lock_get(sdirs->lock);
	switch(sdirs->lock->status)
	{
		case GET_LOCK_GOT: break;
		case GET_LOCK_NOT_GOT:
			logp("Another instance of client is already running.\n");
			asfd->write_str(asfd, CMD_ERROR,
				"another instance is already running");
			goto error;
		case GET_LOCK_ERROR:
		default:
			logp("Problem with lock file on server: %s\n",
				sdirs->lock->path);
			asfd->write_str(asfd, CMD_ERROR,
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
		asfd->write_str(asfd, CMD_ERROR, msg);
		goto finalising;
	}

	return 0;
finalising:
	return 1;
error:
	return -1;
}

static int client_can_restore(struct conf *cconf)
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

static void maybe_do_notification(struct asfd *asfd,
	int status, const char *clientdir,
	const char *storagedir, const char *filename,
	const char *brv, struct conf *cconf)
{
	int a=0;
	const char *args[12];
	struct cntr *cntr=cconf->cntr;
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
		run_script(asfd, args, cconf->n_failure_arg, cconf, 1, 1, 1);
	}
	else if((cconf->n_success_warnings_only
		&& cntr->ent[CMD_WARNING]->count > 0)
	  || (cconf->n_success_changes_only
		&& cntr->ent[CMD_TOTAL]->changed > 0)
	  || (!cconf->n_success_warnings_only
		&& !cconf->n_success_changes_only))
	{
		char warnings[32]="";
		snprintf(warnings, sizeof(warnings), "%llu",
			cntr->ent[CMD_WARNING]->count);
		args[0]=cconf->n_success_script;
		args[a++]=warnings;
		args[a++]=NULL;
		run_script(asfd, args, cconf->n_success_arg, cconf, 1, 1, 1);
	}
}

static int run_restore(struct asfd *asfd,
	struct sdirs *sdirs, struct conf *cconf, int srestore)
{
	int ret=-1;
	char *cp=NULL;
	char *copy=NULL;
	enum action act;
	char *backupnostr=NULL;
	char *restoreregex=NULL;
	char *dir_for_notify=NULL;
	struct iobuf *rbuf=asfd->rbuf;

	if(!(copy=strdup_w(rbuf->buf, __func__)))
		goto end;

	iobuf_free_content(rbuf);

	if(!strncmp_w(copy, "restore ")) act=ACTION_RESTORE;
	else act=ACTION_VERIFY;

	if(!(backupnostr=strchr(copy, ' ')))
	{
		logp("Could not parse %s in %s\n", copy, __func__);
		goto end;
	}
	if(conf_val_reset(backupnostr, &(cconf->backup)))
		goto end;
	if((cp=strchr(cconf->backup, ':'))) *cp='\0';

	if(act==ACTION_RESTORE)
	{
		int r;
		if((r=client_can_restore(cconf))<0)
			goto end;
		else if(!r)
		{
			logp("Not allowing restore of %s\n", cconf->cname);
			if(!asfd->write_str(asfd, CMD_GEN,
				"Client restore is not allowed")) ret=0;
			goto end;
		}
	}
	if(act==ACTION_VERIFY && !cconf->client_can_verify)
	{
		logp("Not allowing verify of %s\n", cconf->cname);
		if(!asfd->write_str(asfd, CMD_GEN,
			"Client verify is not allowed")) ret=0;
		goto end;
	}

	if((restoreregex=strchr(copy, ':')))
	{
		*restoreregex='\0';
		restoreregex++;
	}
	if(conf_val_reset(restoreregex, &(cconf->regex))
	  || asfd->write_str(asfd, CMD_GEN, "ok"))
		goto end;
	ret=do_restore_server(asfd, sdirs, act,
		srestore, &dir_for_notify, cconf);
	if(dir_for_notify)
		maybe_do_notification(asfd, ret,
			sdirs->client, dir_for_notify,
			act==ACTION_RESTORE?"restorelog":"verifylog",
			act==ACTION_RESTORE?"restore":"verify",
			cconf);
end:
	free_w(&copy);
	free_w(&dir_for_notify);
	return ret;
}

static int run_delete(struct asfd *asfd,
	struct sdirs *sdirs, struct conf *cconf)
{
	char *backupno=NULL;
	struct iobuf *rbuf=asfd->rbuf;
	if(!cconf->client_can_delete)
	{
		logp("Not allowing delete of %s\n", cconf->cname);
		asfd->write_str(asfd, CMD_GEN, "Client delete is not allowed");
		return -1;
	}
	backupno=rbuf->buf+strlen("delete ");
	return do_delete_server(asfd, sdirs, cconf, backupno);
}

static int run_list(struct asfd *asfd, struct sdirs *sdirs, struct conf *cconf)
{
	int ret=-1;
	char *cp=NULL;
	char *backupno=NULL;
	char *browsedir=NULL;
	char *listregex=NULL;
	struct iobuf *rbuf=asfd->rbuf;

	if(!cconf->client_can_list)
	{
		logp("Not allowing list of %s\n", cconf->cname);
		asfd->write_str(asfd, CMD_GEN, "Client list is not allowed");
		goto end;
	}

	if(!strncmp_w(rbuf->buf, "list "))
	{
		if((cp=strrchr(rbuf->buf, ':')))
		{
			*cp='\0';
			if(!(listregex=strdup_w(cp+1, __func__)))
				goto end;
		}
		if(!(backupno=strdup_w(rbuf->buf+strlen("list "), __func__)))
			goto end;
		
	}
	else if(!strncmp_w(rbuf->buf, "listb "))
	{
		if((cp=strchr(rbuf->buf, ':')))
		{
			*cp='\0';
			if(!(browsedir=strdup_w(cp+1, __func__)))
				goto end;
		}
		strip_trailing_slashes(&browsedir);
		if(!(backupno=strdup_w(rbuf->buf+strlen("listb "), __func__)))
			goto end;
	}
	if(asfd->write_str(asfd, CMD_GEN, "ok")) goto end;

	iobuf_free_content(asfd->rbuf);

	ret=do_list_server(asfd,
		sdirs, cconf, backupno, listregex, browsedir);
end:
	free_w(&backupno);
	free_w(&browsedir);
	free_w(&listregex);
	return ret;
}

static int run_diff(struct asfd *asfd, struct sdirs *sdirs, struct conf *cconf)
{
	int ret=-1;
	char *backupno=NULL;
	struct iobuf *rbuf=asfd->rbuf;

	if(!cconf->client_can_diff)
	{
		logp("Not allowing diff of %s\n", cconf->cname);
		asfd->write_str(asfd, CMD_GEN, "Client diff is not allowed");
		goto end;
	}

	if(!strncmp_w(rbuf->buf, "diff "))
	{
		if((backupno=strdup_w(rbuf->buf+strlen("diff "), __func__)))
			goto end;
	}
	if(asfd->write_str(asfd, CMD_GEN, "ok")) goto end;

	iobuf_free_content(asfd->rbuf);

	ret=do_diff_server(asfd, sdirs, cconf, backupno);
end:
	return ret;
}

static int unknown_command(struct asfd *asfd)
{
	iobuf_log_unexpected(asfd->rbuf, __func__);
	asfd->write_str(asfd, CMD_ERROR, "unknown command");
	return -1;
}

static const char *buf_to_notify_str(struct iobuf *rbuf)
{
	const char *buf=rbuf->buf;
	if(!strncmp_w(buf, "backup")) return "backup";
	else if(!strncmp_w(buf, "restore")) return "restore";
	else if(!strncmp_w(buf, "verify")) return "verify";
	else if(!strncmp_w(buf, "delete")) return "delete";
	else if(!strncmp_w(buf, "list")) return "list";
	else return "unknown";
}

static int check_for_rubble(struct asfd *asfd, struct sdirs *sdirs,
	const char *incexc, int *resume, struct conf *cconf)
{
	if(cconf->protocol==PROTO_BURP1)
		return check_for_rubble_burp1(asfd,
			sdirs, incexc, resume, cconf);
	else
		return check_for_rubble_burp2(asfd,
			sdirs, incexc, resume, cconf);
}

int run_action_server(struct async *as, struct sdirs *sdirs,
	const char *incexc, int srestore, int *timer_ret, struct conf *cconf)
{
	int ret;
	int resume=0;
	char msg[256]="";
	struct iobuf *rbuf=as->asfd->rbuf;

	// Make sure some directories exist.
	if(mkpath(&sdirs->current, sdirs->dedup))
	{
		snprintf(msg, sizeof(msg),
			"could not mkpath %s", sdirs->current);
		log_and_send(as->asfd, msg);
		return -1;
	}

	if(rbuf->cmd!=CMD_GEN) return unknown_command(as->asfd);

	if((ret=get_lock_sdirs(as->asfd, sdirs)))
	{
		// -1 on error or 1 if the backup is still finalising.
		if(ret<0) maybe_do_notification(as->asfd, ret,
			"", "error in get_lock_sdirs()",
			"", buf_to_notify_str(rbuf), cconf);
		return ret;
	}

	if(check_for_rubble(as->asfd, sdirs, incexc, &resume, cconf))
	{
		maybe_do_notification(as->asfd, ret,
			"", "error in check_for_rubble()",
			"", buf_to_notify_str(rbuf), cconf);
		return -1;
	}

	if(!strncmp_w(rbuf->buf, "backup"))
	{
		ret=run_backup(as, sdirs, cconf, incexc, timer_ret, resume);
		if(*timer_ret<0)
			maybe_do_notification(as->asfd, ret, "",
				"error running timer script",
				"", "backup", cconf);
		else if(!*timer_ret)
			maybe_do_notification(as->asfd, ret, sdirs->client,
				sdirs->current, "log", "backup", cconf);
		return ret;
	}

	if(!strncmp_w(rbuf->buf, "restore ")
	  || !strncmp_w(rbuf->buf, "verify "))
		return run_restore(as->asfd, sdirs, cconf, srestore);

	if(!strncmp_w(rbuf->buf, "list ")
	  || !strncmp_w(rbuf->buf, "listb "))
		return run_list(as->asfd, sdirs, cconf);

	if(!strncmp_w(rbuf->buf, "diff "))
		return run_diff(as->asfd, sdirs, cconf);

	if(!strncmp_w(rbuf->buf, "Delete "))
		return run_delete(as->asfd, sdirs, cconf);

	// Old clients will send 'delete', possibly accidentally due to the
	// user trying to use the new diff/long diff options.
	// Stop them from working, just to be safe.
	if(!strncmp_w(rbuf->buf, "delete "))
	{
		logp("old style delete from %s denied\n", cconf->cname);
		as->asfd->write_str(as->asfd, CMD_ERROR,
			"old style delete is not supported on this server");
		return -1;
	}

	return unknown_command(as->asfd);
}
