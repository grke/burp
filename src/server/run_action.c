#include "../burp.h"
#include "../action.h"
#include "../asfd.h"
#include "../async.h"
#include "../cmd.h"
#include "../cntr.h"
#include "../handy.h"
#include "../fsops.h"
#include "../iobuf.h"
#include "../lock.h"
#include "../log.h"
#include "../regexp.h"
#include "../run_script.h"
#include "backup.h"
#include "delete.h"
#include "diff.h"
#include "list.h"
#include "protocol2/restore.h"
#include "restore.h"
#include "rubble.h"
#include "sdirs.h"
#include "run_action.h"
#include "timestamp.h"

// FIX THIS: Somewhat haphazard.
/* Return 0 for everything OK. -1 for error, or 1 to mean that there was
   another process that has the lock. */
static int get_lock_sdirs_for_write(struct asfd *asfd, struct sdirs *sdirs)
{
	struct stat statp;

	// Make sure the lock directory exists.
	if(mkpath(&sdirs->lock_storage_for_write->path, sdirs->lockdir))
	{
		asfd->write_str(asfd, CMD_ERROR, "problem with lock directory");
		goto error;
	}

	lock_get(sdirs->lock_storage_for_write);
	switch(sdirs->lock_storage_for_write->status)
	{
		case GET_LOCK_GOT: break;
		case GET_LOCK_NOT_GOT:
			if(!lstat(sdirs->finishing, &statp))
			{
				char msg[256]="";
				logp("finalising previous backup\n");
				snprintf(msg, sizeof(msg),
					"Finalising previous backup of client. "
					"Please try again later.");
				asfd->write_str(asfd, CMD_ERROR, msg);
			}
			else
			{
				logp("Another instance of client is already running.\n");
				asfd->write_str(asfd, CMD_ERROR,
					"another instance is already running");
			}
			goto lockedout;
		case GET_LOCK_ERROR:
		default:
			logp("Problem with lock file on server: %s\n",
				sdirs->lock_storage_for_write->path);
			asfd->write_str(asfd, CMD_ERROR,
				"problem with lock file on server");
			goto error;
	}

	return 0;
lockedout:
	return 1;
error:
	return -1;
}

static int client_can_generic(struct conf **cconfs, enum conf_opt o)
{
	return get_int(cconfs[o]);
}

int client_can_monitor(struct conf **cconfs)
{
	return client_can_generic(cconfs, OPT_CLIENT_CAN_MONITOR);
}

static int client_can_restore(struct conf **cconfs)
{
	const char *restore_path=get_string(cconfs[OPT_RESTORE_PATH]);

	// If there is a restore file on the server, it is always OK.
	if(restore_path && is_reg_lstat(restore_path)==1)
	{
		// Remove the file.
		unlink(restore_path);
		return 1;
	}

	return client_can_generic(cconfs, OPT_CLIENT_CAN_RESTORE);
}

static void maybe_do_notification(struct asfd *asfd,
	int status, const char *clientdir,
	const char *storagedir, const char *filename,
	const char *brv, struct conf **cconfs)
{
	int a=0;
	const char *args[12];
	struct cntr *cntr=get_cntr(cconfs);
	args[a++]=NULL; // Fill in the script name later.
	args[a++]=get_string(cconfs[OPT_CNAME]);
	args[a++]=clientdir;
	args[a++]=storagedir;
	args[a++]=filename;
	args[a++]=brv;
	if(status)
	{
		args[0]=get_string(cconfs[OPT_N_FAILURE_SCRIPT]);
		args[a++]="0";
		args[a++]=NULL;
		run_script(asfd, args, get_strlist(cconfs[OPT_N_FAILURE_ARG]),
			cconfs, 1, 1, 1);
	}
	else if((get_int(cconfs[OPT_N_SUCCESS_WARNINGS_ONLY])
		&& cntr->ent[CMD_WARNING]->count > 0)
	  || (get_int(cconfs[OPT_N_SUCCESS_CHANGES_ONLY])
		&& cntr->ent[CMD_TOTAL]->changed > 0)
	  || (!get_int(cconfs[OPT_N_SUCCESS_WARNINGS_ONLY])
	        && !get_int(cconfs[OPT_N_SUCCESS_CHANGES_ONLY])))
	{
		char warnings[32]="";
		snprintf(warnings, sizeof(warnings), "%" PRIu64,
			cntr->ent[CMD_WARNING]->count);
		args[0]=get_string(cconfs[OPT_N_SUCCESS_SCRIPT]);
		args[a++]=warnings;
		args[a++]=NULL;
		run_script(asfd, args, get_strlist(cconfs[OPT_N_SUCCESS_ARG]),
			cconfs, 1, 1, 1);
	}
}

static int parse_restore_str(
	const char *str,
	enum action *act,
	int *input,
	char **backupnostr,
	char **restoreregex
) {
	int ret=-1;
	char *cp=NULL;
	char *copy=NULL;

	if(!str)
	{
		logp("NULL passed to %s\n", __func__);
		goto end;
	}

	if(!(copy=strdup_w(str, __func__)))
		goto end;

	if(!strncmp_w(copy, "restore "))
		*act=ACTION_RESTORE;
	else if(!strncmp_w(copy, "verify "))
		*act=ACTION_VERIFY;
	else
	{
		logp("Could not parse %s in %s\n", copy, __func__);
		goto end;
	}

	if(!(cp=strchr(copy, ' ')))
	{
		logp("Could not parse %s in %s\n", copy, __func__);
		goto end;
	}
	cp++;
	*input=0;
	if(!strncmp_w(cp, "restore_list "))
	{
		cp+=strlen("restore_list ");
		*input=1;
	}
	if(!(*backupnostr=strdup_w(cp, __func__)))
		goto end;
	if((cp=strchr(*backupnostr, ':')))
	{
		*cp='\0';
		cp++;
		if(!(*restoreregex=strdup_w(cp, __func__)))
			goto end;
	}

	ret=0;
end:
	free_w(&copy);
	return ret;
}

#ifndef UTEST
static
#endif
int parse_restore_str_and_set_confs(const char *str, enum action *act,
	struct conf **cconfs)
{
	int ret=-1;
	int input=0;
	char *backupnostr=NULL;
	char *restoreregex=NULL;

	if(parse_restore_str(str, act, &input, &backupnostr, &restoreregex))
		goto end;

	if(set_string(cconfs[OPT_RESTORE_LIST], input?"":NULL))
		goto end;
	if(set_string(cconfs[OPT_BACKUP], backupnostr))
		goto end;
	if(restoreregex && *restoreregex
	  && set_string(cconfs[OPT_REGEX], restoreregex))
		goto end;
	ret=0;
end:
	free_w(&backupnostr);
	free_w(&restoreregex);
	return ret;
}

static int run_restore(struct asfd *asfd,
	struct sdirs *sdirs, struct conf **cconfs, int srestore)
{
	int ret=-1;
	char *dir_for_notify=NULL;
	enum action act=ACTION_RESTORE;
	struct iobuf *rbuf=asfd->rbuf;
	const char *cname=get_string(cconfs[OPT_CNAME]);

	if(parse_restore_str_and_set_confs(rbuf->buf, &act, cconfs))
		goto end;

	iobuf_free_content(rbuf);

	if(act==ACTION_RESTORE)
	{
		int r;
		if((r=client_can_restore(cconfs))<0)
			goto end;
		else if(!r)
		{
			logp("Not allowing restore of %s\n", cname);
			if(!asfd->write_str(asfd, CMD_GEN,
				"Client restore is not allowed")) ret=0;
			goto end;
		}
	}
	if(act==ACTION_VERIFY
	  && !(client_can_generic(cconfs, OPT_CLIENT_CAN_VERIFY)))
	{
		logp("Not allowing verify of %s\n", cname);
		if(!asfd->write_str(asfd, CMD_GEN,
			"Client verify is not allowed")) ret=0;
		goto end;
	}

	if(get_string(cconfs[OPT_RESTORE_LIST]))
	{
		// Should start receiving the input file here.
		if(asfd->write_str(asfd, CMD_GEN, "ok restore_list"))
			goto end;
		if(receive_a_file(asfd, sdirs->restore_list, get_cntr(cconfs)))
		{
			goto end;
		}
	}
	else
	{
		if(asfd->write_str(asfd, CMD_GEN, "ok"))
			goto end;
	}

	ret=do_restore_server(asfd, sdirs, act,
		srestore, &dir_for_notify, cconfs);
	if(dir_for_notify)
		maybe_do_notification(asfd, ret,
			sdirs->client, dir_for_notify,
			act==ACTION_RESTORE?"restorelog":"verifylog",
			act==ACTION_RESTORE?"restore":"verify",
			cconfs);
end:
	free_w(&dir_for_notify);
	return ret;
}

static int run_delete(struct asfd *asfd,
	struct sdirs *sdirs, struct conf **cconfs)
{
	char *backupno=NULL;
	struct iobuf *rbuf=asfd->rbuf;
	const char *cname=get_string(cconfs[OPT_CNAME]);
	if(!client_can_generic(cconfs, OPT_CLIENT_CAN_DELETE))
	{
		logp("Not allowing delete of %s\n", cname);
		asfd->write_str(asfd, CMD_GEN, "Client delete is not allowed");
		return -1;
	}
	backupno=rbuf->buf+strlen("delete ");
	return do_delete_server(asfd, sdirs,
		get_cntr(cconfs), cname, backupno,
		get_string(cconfs[OPT_MANUAL_DELETE]));
}

static int run_list(struct asfd *asfd,
	struct sdirs *sdirs, struct conf **cconfs)
{
	int ret=-1;
	char *cp=NULL;
	char *backupno=NULL;
	char *browsedir=NULL;
	char *listregex=NULL;
	struct iobuf *rbuf=asfd->rbuf;

	if(!client_can_generic(cconfs, OPT_CLIENT_CAN_LIST))
	{
		logp("Not allowing list of %s\n",
			get_string(cconfs[OPT_CNAME]));
		asfd->write_str(asfd, CMD_GEN, "Client list is not allowed");
		goto end;
	}

	if(!strncmp_w(rbuf->buf, "list "))
	{
		if((cp=strchr(rbuf->buf, ':')))
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

	if(list_server_init(asfd, sdirs, get_cntr(cconfs),
		get_protocol(cconfs), backupno, listregex, browsedir))
			goto end;
	ret=do_list_server();
end:
	free_w(&backupno);
	free_w(&browsedir);
	free_w(&listregex);
	list_server_free();
	return ret;
}

static int run_diff(struct asfd *asfd,
	struct sdirs *sdirs, struct conf **cconfs)
{
	int ret=-1;
	char *backup1=NULL;
	char *backup2=NULL;
	struct iobuf *rbuf=asfd->rbuf;

	if(!client_can_generic(cconfs, OPT_CLIENT_CAN_DIFF))
	{
		logp("Not allowing diff of %s\n",
			get_string(cconfs[OPT_CNAME]));
		asfd->write_str(asfd, CMD_GEN, "Client diff is not allowed");
		goto end;
	}

	if(!strncmp_w(rbuf->buf, "diff "))
	{
		char *cp;
		if((cp=strchr(rbuf->buf, ':')))
		{
			*cp='\0';
			if(!(backup2=strdup_w(cp+1, __func__)))
				goto end;
		}
		if(!(backup1=strdup_w(rbuf->buf+strlen("diff "), __func__)))
			goto end;
	}
	if(asfd->write_str(asfd, CMD_GEN, "ok")) goto end;

	iobuf_free_content(asfd->rbuf);

	ret=do_diff_server(asfd, sdirs,
		get_cntr(cconfs), get_protocol(cconfs), backup1, backup2);
end:
	free_w(&backup1);
	free_w(&backup2);
	return ret;
}

static int unknown_command(struct asfd *asfd, const char *func)
{
	iobuf_log_unexpected(asfd->rbuf, func);
	asfd->write_str(asfd, CMD_ERROR, "unknown command");
	return -1;
}

static const char *buf_to_notify_str(struct iobuf *rbuf)
{
	const char *buf=rbuf->buf;
	if(!strncmp_w(buf, "backup")) return "backup";
	else if(!strncmp_w(buf, "delete")) return "delete";
	else if(!strncmp_w(buf, "diff")) return "diff";
	else if(!strncmp_w(buf, "list")) return "list";
	else if(!strncmp_w(buf, "restore")) return "restore";
	else if(!strncmp_w(buf, "verify")) return "verify";
	else return "unknown";
}

static int maybe_write_first_created_file(struct sdirs *sdirs,
	const char *tstmp)
{
	if(is_reg_lstat(sdirs->created)>0
	  || is_lnk_lstat(sdirs->current)>0
	  || is_lnk_lstat(sdirs->currenttmp)>0
	  || is_lnk_lstat(sdirs->working)>0
	  || is_lnk_lstat(sdirs->finishing)>0)
		return 0;

	return timestamp_write(sdirs->created, tstmp);
}

static int log_command(struct async *as,
	struct sdirs *sdirs, struct conf **cconfs, const char *tstmp)
{
	struct fzp *fzp=NULL;
	struct asfd *asfd=as->asfd;
	struct iobuf *rbuf=asfd->rbuf;
	char *cname=get_string(cconfs[OPT_CONNECT_CLIENT]);

	if(rbuf->cmd!=CMD_GEN)
		return 0;

	if(!(fzp=fzp_open(sdirs->command, "a")))
		return -1;
	fzp_printf(fzp, "%s %s %s %s\n", tstmp, asfd->peer_addr, cname,
		iobuf_to_printable(rbuf));
	if(fzp_close(&fzp))
		return -1;

	return 0;
}

static int run_action_server_do(struct async *as, struct sdirs *sdirs,
	const char *incexc, int srestore, int *timer_ret, struct conf **cconfs)
{
	int ret;
	int resume=0;
	char msg[256]="";
	char tstmp[48]="";
	struct iobuf *rbuf=as->asfd->rbuf;

	// Make sure some directories exist.
	if(mkpath(&sdirs->current, sdirs->dedup))
	{
		snprintf(msg, sizeof(msg),
			"could not mkpath %s", sdirs->current);
		log_and_send(as->asfd, msg);
		return -1;
	}

	if(timestamp_get_new(/*index*/0,
		tstmp, sizeof(tstmp),
		/*bufforfile*/NULL, /*bs*/0,
		/*format*/NULL))
			return -1;

	// Carry on if these fail, otherwise you will not be able to restore
	// from readonly backups.
	maybe_write_first_created_file(sdirs, tstmp);
	log_command(as, sdirs, cconfs, tstmp);

	if(rbuf->cmd!=CMD_GEN)
		return unknown_command(as->asfd, __func__);

	// List and diff should work well enough without needing to lock
	// anything.
	if(!strncmp_w(rbuf->buf, "list ")
	  || !strncmp_w(rbuf->buf, "listb "))
		return run_list(as->asfd, sdirs, cconfs);

	if(!strncmp_w(rbuf->buf, "diff "))
		return run_diff(as->asfd, sdirs, cconfs);

	// Old clients will send 'delete', possibly accidentally due to the
	// user trying to use the new diff/long diff options.
	// Stop them from working, just to be safe.
	if(!strncmp_w(rbuf->buf, "delete "))
	{
		logp("old style delete from %s denied\n",
			get_string(cconfs[OPT_CNAME]));
		as->asfd->write_str(as->asfd, CMD_ERROR,
			"old style delete is not supported on this server");
		return -1;
	}

	// Restore and verify should work well enough by locking only the
	// backup directory they are interested in.
	if(!strncmp_w(rbuf->buf, "restore ")
	  || !strncmp_w(rbuf->buf, "verify "))
	{
		ret=run_restore(as->asfd, sdirs, cconfs, srestore);
		unlink(sdirs->restore_list);
		return ret;
	}

	if(strncmp_w(rbuf->buf, "backup")
	  && strncmp_w(rbuf->buf, "Delete "))
		return unknown_command(as->asfd, __func__);

	// Beyond this point, only need to deal with backup and delete.
	// These require locking out all other backups and deletes.

	switch((ret=get_lock_sdirs_for_write(as->asfd, sdirs)))
	{
		case 0: break; // OK.
		case 1: return 1; // Locked out.
		default: // Error.
			maybe_do_notification(as->asfd, ret,
				"", "error in get_lock_sdirs()",
				"", buf_to_notify_str(rbuf), cconfs);
			return -1;
	}

	switch((ret=check_for_rubble_and_clean(as, sdirs,
		incexc, &resume, cconfs)))
	{
		case 0: break; // OK.
		case 1: return 1; // Now finalising.
		default: // Error.
			maybe_do_notification(as->asfd, ret,
				"", "error in check_for_rubble()",
				"", buf_to_notify_str(rbuf), cconfs);
			return -1;
	}

	if(!strncmp_w(rbuf->buf, "Delete "))
		return run_delete(as->asfd, sdirs, cconfs);

	// Only backup action left to deal with.
	ret=run_backup(as, sdirs,
		cconfs, incexc, timer_ret, resume);

	// If this is a backup failure and the client has more servers
	// to failover to, do not notify.
	if(ret
	  && get_int(cconfs[OPT_N_FAILURE_BACKUP_FAILOVERS_LEFT])
	  && get_int(cconfs[OPT_BACKUP_FAILOVERS_LEFT]))
		return ret;

	if(*timer_ret<0)
		maybe_do_notification(as->asfd, ret,
			"", "error running timer script",
			"", "backup", cconfs);
	else if(!*timer_ret)
		maybe_do_notification(as->asfd, ret,
			sdirs->client, sdirs->current,
			"log", "backup", cconfs);
	return ret;
}

int run_action_server(struct async *as,
	const char *incexc, int srestore, int *timer_ret, struct conf **cconfs)
{
	int ret=-1;
        struct sdirs *sdirs=NULL;
        if((sdirs=sdirs_alloc())
          && !sdirs_init_from_confs(sdirs, cconfs))
		ret=run_action_server_do(as,
			sdirs, incexc, srestore, timer_ret, cconfs);
        if(sdirs) lock_release(sdirs->lock_storage_for_write);
        sdirs_free(&sdirs);
	return ret;
}
