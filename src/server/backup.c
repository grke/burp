#include "server/backup.h"
#include "server/auth.h"
#include "server/backup_phase1.h"
#include "server/backup_phase3.h"
#include "server/compress.h"
#include "server/delete.h"
#include "server/sdirs.h"
#include "server/protocol1/backup_phase2.h"
#include "server/protocol1/backup_phase4.h"
#include "server/protocol2/backup_phase2.h"
#include "server/protocol2/backup_phase4.h"
#include "burp.h"
#include "action.h"
#include "alloc.h"
#include "asfd.h"
#include "async.h"
#include "conf.h"
#include "cmd.h"
#include "cntr.h"
#include "fsops.h"
#include "handy.h"
#include "iobuf.h"
#include "log.h"
#include "run_script.h"

static int open_log(struct asfd *asfd,
	struct sdirs *sdirs, struct conf **cconfs)
{
	int ret=-1;
	char *logpath=NULL;
	const char *peer_version=get_string(cconfs[OPT_PEER_VERSION]);

	if(!(logpath=prepend_s(sdirs->rworking, "log"))) goto end;
	if(log_fzp_set(logpath, cconfs))
	{
		logp("could not open log file: %s\n", logpath);
		goto end;
	}

	logp("Client version: %s\n", peer_version?:"");
	logp("Protocol: %d\n", (int)get_protocol(cconfs));
	if(get_int(cconfs[OPT_CLIENT_IS_WINDOWS]))
		logp("Client is Windows\n");

	// Make sure a warning appears in the backup log.
	// The client will already have been sent a message with logw.
	// This time, prevent it sending a logw to the client by specifying
	// NULL for cntr.
	if(get_int(cconfs[OPT_VERSION_WARN])) version_warn(asfd, NULL, cconfs);

	ret=0;
end:
	free_w(&logpath);
	return ret;
}

static int write_incexc(const char *realworking, const char *incexc)
{
	int ret=-1;
	struct fzp *fzp=NULL;
	char *path=NULL;
	if(!incexc || !*incexc) return 0;
	if(!(path=prepend_s(realworking, "incexc"))
	  || !(fzp=fzp_open(path, "wb")))
		goto end;
	fzp_printf(fzp, "%s", incexc);
	ret=0;
end:
	if(fzp_close(&fzp))
	{
		logp("error writing to %s in write_incexc\n", path);
		ret=-1;
	}
	free_w(&path);
	return ret;
}

static int backup_phase1_server(struct async *as,
	struct sdirs *sdirs, struct conf **cconfs)
{
	int breaking=get_int(cconfs[OPT_BREAKPOINT]);
	if(breaking==1)
		return breakpoint(breaking, __func__);
	return backup_phase1_server_all(as, sdirs, cconfs);
}

static int backup_phase2_server(struct async *as, struct sdirs *sdirs,
	const char *incexc, int resume, struct conf **cconfs)
{
	int breaking=get_int(cconfs[OPT_BREAKPOINT]);
	if(breaking==2)
		return breakpoint(breaking, __func__);

	switch(get_protocol(cconfs))
	{
		case PROTO_1:
			return backup_phase2_server_protocol1(as, sdirs,
				incexc, resume, cconfs);
		default:
			return backup_phase2_server_protocol2(as, sdirs,
				resume, cconfs);
	}
}

static int backup_phase3_server(struct sdirs *sdirs, struct conf **cconfs)
{
	int breaking=get_int(cconfs[OPT_BREAKPOINT]);
	if(breaking==3)
		return breakpoint(breaking, __func__);

	return backup_phase3_server_all(sdirs, cconfs);
}

static int backup_phase4_server(struct sdirs *sdirs, struct conf **cconfs)
{
	int breaking=get_int(cconfs[OPT_BREAKPOINT]);
	if(breaking==4)
		return breakpoint(breaking, __func__);

	log_fzp_set(NULL, cconfs);
	// Phase4 will open logfp again (in case it is resuming).
	switch(get_protocol(cconfs))
	{
		case PROTO_1:
			return backup_phase4_server_protocol1(sdirs, cconfs);
		default:
			return backup_phase4_server_protocol2(sdirs, cconfs);
	}
}

static void log_rshash(struct conf **confs)
{
	if(get_protocol(confs)!=PROTO_1) return;
	logp("Using librsync hash %s\n",
		rshash_to_str(get_e_rshash(confs[OPT_RSHASH])));
}

static int do_backup_server(struct async *as, struct sdirs *sdirs,
	struct conf **cconfs, const char *incexc, int resume)
{
	int ret=0;
	int do_phase2=1;
	struct asfd *asfd=as->asfd;
	enum protocol protocol=get_protocol(cconfs);

	logp("in do_backup_server\n");

	log_rshash(cconfs);

	if(resume)
	{
		if(sdirs_get_real_working_from_symlink(sdirs)
		  || sdirs_get_real_manifest(sdirs, protocol)
		  || open_log(asfd, sdirs, cconfs))
			goto error;
	}
	else
	{
		// Not resuming - need to set everything up fresh.
		if(sdirs_create_real_working(sdirs,
			get_string(cconfs[OPT_TIMESTAMP_FORMAT]))
		  || sdirs_get_real_manifest(sdirs, protocol)
		  || open_log(asfd, sdirs, cconfs))
			goto error;

		if(write_incexc(sdirs->rworking, incexc))
		{
			logp("unable to write incexc\n");
			goto error;
		}

		if(backup_phase1_server(as, sdirs, cconfs))
		{
			logp("error in phase 1\n");
			goto error;
		}
	}

	if(resume)
	{
		struct stat statp;
		if(lstat(sdirs->phase1data, &statp)
		  && !lstat(sdirs->changed, &statp)
		  && !lstat(sdirs->unchanged, &statp))
		{
			// In this condition, it looks like there was an
			// interruption during phase3. Skip phase2.
			do_phase2=0;
		}
	}

	if(do_phase2)
	{
		if(backup_phase2_server(as, sdirs, incexc, resume, cconfs))
		{
			logp("error in backup phase 2\n");
			goto error;
		}

		asfd->write_str(asfd, CMD_GEN, "okbackupend");
	}

	// Close the connection with the client, the rest of the job we can do
	// by ourselves.
	logp("Backup ending - disconnect from client.\n");
	if(asfd_flush_asio(asfd)) goto end;
	as->asfd_remove(as, asfd);
	asfd_close(asfd);

	if(backup_phase3_server(sdirs, cconfs))
	{
		logp("error in backup phase 3\n");
		goto error;
	}

	if(do_rename(sdirs->working, sdirs->finishing))
		goto error;

	if(backup_phase4_server(sdirs, cconfs))
	{
		logp("error in backup phase 4\n");
		goto error;
	}

	cntr_print(get_cntr(cconfs), ACTION_BACKUP);
	cntr_stats_to_file(get_cntr(cconfs),
		sdirs->rworking, ACTION_BACKUP, cconfs);

	// Move the symlink to indicate that we are now in the end phase. The
	// rename() race condition is automatically recoverable here.
	if(do_rename(sdirs->finishing, sdirs->current)) goto error;

	logp("Backup completed.\n");
	log_fzp_set(NULL, cconfs);
	compress_filename(sdirs->rworking,
		"log", "log.gz", get_int(cconfs[OPT_COMPRESSION]));

	goto end;
error:
	ret=-1;
end:

	log_fzp_set(NULL, cconfs);
	return ret;
}

int run_backup(struct async *as, struct sdirs *sdirs, struct conf **cconfs,
	const char *incexc, int *timer_ret, int resume)
{
	int ret;
	char okstr[32]="";
	struct asfd *asfd=as->asfd;
	struct iobuf *rbuf=asfd->rbuf;
	const char *cname=get_string(cconfs[OPT_CNAME]);

	if(get_string(cconfs[OPT_RESTORE_CLIENT]))
	{
		// This client is not the original client, so a backup might
		// cause all sorts of trouble.
		logp("Not allowing backup of %s\n", cname);
		return asfd->write_str(asfd, CMD_GEN, "Backup is not allowed");
	}

	// Set quality of service bits on backups.
	asfd->set_bulk_packets(asfd);

	if(!strncmp_w(rbuf->buf, "backupphase1timed"))
	{
		int a=0;
		const char *args[12];
		int checkonly=!strncmp_w(rbuf->buf, "backupphase1timedcheck");
		if(checkonly) logp("Client asked for a timer check only.\n");

		args[a++]=get_string(cconfs[OPT_TIMER_SCRIPT]);
		args[a++]=cname;
		args[a++]=sdirs->current;
		args[a++]=sdirs->clients;
		args[a++]="reserved1";
		args[a++]="reserved2";
		args[a++]=NULL;
		if((*timer_ret=run_script(asfd, args,
		  get_strlist(cconfs[OPT_TIMER_ARG]),
		  cconfs,
		  1 /* wait */,
		  1 /* use logp */,
		  0 /* no log_remote */
		))<0)
		{
			logp("Error running timer script for %s\n",
				cname);
			return *timer_ret;
		}
		if(*timer_ret)
		{
			if(!checkonly)
				logp("Not running backup of %s\n",
					cname);
			return asfd->write_str(asfd,
				CMD_GEN, "timer conditions not met");
		}
		if(checkonly)
		{
			logp("Client asked for a timer check only,\n");
			logp("so a backup is not happening right now.\n");
			return asfd->write_str(asfd,
				CMD_GEN, "timer conditions met");
		}
		logp("Running backup of %s\n", cname);
	}
	else if(!get_int(cconfs[OPT_CLIENT_CAN_FORCE_BACKUP]))
	{
		logp("Not allowing forced backup of %s\n", cname);
		return asfd->write_str(asfd,
			CMD_GEN, "Forced backup is not allowed");
	}

	snprintf(okstr, sizeof(okstr), "%s:%d",
		resume?"resume":"ok", get_int(cconfs[OPT_COMPRESSION]));
	if(asfd->write_str(asfd, CMD_GEN, okstr)) return -1;

	if((ret=do_backup_server(as, sdirs, cconfs, incexc, resume)))
		goto end;
	if((ret=delete_backups(sdirs, cname,
		get_strlist(cconfs[OPT_KEEP]),
		get_string(cconfs[OPT_MANUAL_DELETE]))))
			goto end;
	if(get_protocol(cconfs)==PROTO_2)
		ret=regenerate_client_dindex(sdirs);
end:
	return ret;
}
