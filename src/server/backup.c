#include "../burp.h"
#include "../action.h"
#include "../alloc.h"
#include "../asfd.h"
#include "../async.h"
#include "../conf.h"
#include "../cmd.h"
#include "../cntr.h"
#include "../fsops.h"
#include "../handy.h"
#include "../iobuf.h"
#include "../log.h"
#include "../run_script.h"
#include "auth.h"
#include "backup_phase1.h"
#include "backup_phase3.h"
#include "bu_get.h"
#include "compress.h"
#include "delete.h"
#include "sdirs.h"
#include "protocol1/backup_phase2.h"
#include "protocol1/backup_phase4.h"
#include "protocol2/backup_phase2.h"
#include "protocol2/backup_phase4.h"
#include "backup.h"
#include "rubble.h"
#include "timer.h"

static void log_rshash(struct conf **confs)
{
	if(get_protocol(confs)!=PROTO_1) return;
	logp("Using librsync hash %s\n",
		rshash_to_str(get_e_rshash(confs[OPT_RSHASH])));
}

static int open_log(struct asfd *asfd,
	struct sdirs *sdirs, struct conf **cconfs, int resume)
{
	int ret=-1;
	char *logpath=NULL;
	const char *peer_version=get_string(cconfs[OPT_PEER_VERSION]);

	logp("Backup %s: %s\n", resume?"resumed":"started", sdirs->rworking);

	if(!(logpath=prepend_s(sdirs->rworking, "log"))) goto end;
	if(log_fzp_set(logpath, cconfs))
	{
		logp("could not open log file: %s\n", logpath);
		goto end;
	}

	logp("Backup %s\n", resume?"resumed":"started");
	logp("Client version: %s\n", peer_version?:"");
	logp("Protocol: %d\n", (int)get_protocol(cconfs));
	log_rshash(cconfs);
	if(get_int(cconfs[OPT_CLIENT_IS_WINDOWS]))
		logp("Client is Windows\n");

	// Make sure a warning appears in the backup log.
	// The client will already have been sent a message with logw.
	// This time, prevent it sending a logw to the client by specifying
	// NULL for asfd and cntr.
	if(get_int(cconfs[OPT_VERSION_WARN]))
		version_warn(NULL, NULL, cconfs);

	ret=0;
end:
	free_w(&logpath);
	return ret;
}

static int write_incexc(const char *realworking, const char *incexc)
{
	int ret=-1;
	char *tmp=NULL;
	char *path=NULL;
	struct fzp *fzp=NULL;

	if(!incexc || !*incexc) return 0;

	if(!(path=prepend_s(realworking, "incexc"))
	  || !(tmp=prepend(path, ".tmp"))
	  || !(fzp=fzp_open(tmp, "wb")))
		goto end;

	fzp_printf(fzp, "%s", incexc);
	if(fzp_close(&fzp))
	{
		logp("error writing to %s in %s\n", tmp, __func__);
		goto end;
	}
	if(do_rename(tmp, path))
		goto end;
	ret=0;
end:
	free_w(&path);
	free_w(&tmp);
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

static int get_bno_from_sdirs(struct sdirs *sdirs)
{
	char *cp=NULL;
	// Should be easier than this.
	if(!(cp=strrchr(sdirs->rworking, '/')))
		return 0;
	return atoi(cp+1);
}

static uint64_t get_new_bno(struct sdirs *sdirs)
{
	uint64_t index=0;
	struct bu *bu=NULL;
	struct bu *bu_list=NULL;

	// Want to prefix the timestamp with an index that increases by
	// one each time. This makes it far more obvious which backup depends
	// on which - even if the system clock moved around.

	// This function orders the array with the highest index number last.
	if(bu_get_list(sdirs, &bu_list))
		return -1;
	for(bu=bu_list; bu; bu=bu->next)
		if(!bu->next)
			index=bu->bno;
	bu_list_free(&bu_list);

	return index+1;
}

static int do_backup_server(struct async *as, struct sdirs *sdirs,
	struct conf **cconfs, const char *incexc, int resume,
	uint64_t bno_new)
{
	int ret=0;
	int do_phase2=1;
	struct asfd *asfd=as->asfd;
	enum protocol protocol=get_protocol(cconfs);
	struct cntr *cntr=get_cntr(cconfs);

	if(resume)
	{
		if(sdirs_get_real_working_from_symlink(sdirs)
		  || sdirs_get_real_manifest(sdirs, protocol))
			goto error;

		if(open_log(asfd, sdirs, cconfs, resume))
			goto error;

		if(!(cntr->bno=get_bno_from_sdirs(sdirs)))
		{
			logp("Could not get old backup number when resuming.");
			goto error;
		}
	}
	else
	{
		// Not resuming - need to set everything up fresh.
		cntr->bno=bno_new;
		if(sdirs_create_real_working(sdirs, bno_new,
			get_string(cconfs[OPT_TIMESTAMP_FORMAT]))
		  || sdirs_get_real_manifest(sdirs, protocol))
			goto error;

		if(open_log(asfd, sdirs, cconfs, resume))
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
	if(asfd_flush_asio(asfd))
		goto error;
	as->asfd_remove(as, asfd);
	asfd_close(asfd);

	if(backup_phase3_server(sdirs, cconfs))
	{
		logp("error in backup phase 3\n");
		goto error;
	}

	// Write backup_stats before flipping the symlink, so that is there
	// even if phase4 is interrupted.
	cntr_set_bytes(cntr, asfd);
	if(cntr_stats_to_file(cntr, sdirs->working, ACTION_BACKUP))
		goto error;
	unlink(sdirs->counters_d);
	unlink(sdirs->counters_n);

	if(do_rename(sdirs->working, sdirs->finishing))
		goto error;

	if(backup_phase4_server(sdirs, cconfs))
	{
		logp("error in backup phase 4\n");
		goto error;
	}

	cntr_print(cntr, ACTION_BACKUP);

	if(protocol==PROTO_2)
	{
		// Regenerate dindex before the symlink is renamed, so that the
		// champ chooser cleanup does not try to remove data files
		// whilst the dindex regeneration is happening.
		if(regenerate_client_dindex(sdirs))
			goto error;
	}

	// Move the symlink to indicate that we are now in the end phase. The
	// rename() race condition is automatically recoverable here.
	if(do_rename(sdirs->finishing, sdirs->current))
		goto error;

	logp("Backup completed.\n");
	log_fzp_set(NULL, cconfs);
	logp("Backup completed: %s\n", sdirs->rworking);
	compress_filename(sdirs->rworking,
		"log", "log.gz", get_int(cconfs[OPT_COMPRESSION]));

	goto end;
error:
	ret=-1;
end:

	if(ret)
		logp("Backup failed\n");
	log_fzp_set(NULL, cconfs);
	if(ret)
	{
		// Make an entry in the main output, for failed backups.
		logp("Backup failed: %s\n", sdirs->rworking);
	}
	return ret;
}

int run_backup(struct async *as, struct sdirs *sdirs, struct conf **cconfs,
	const char *incexc, int *timer_ret, int resume)
{
	int ret;
	uint64_t bno_new;
	char okstr[32]="";
	struct asfd *asfd=as->asfd;
	struct iobuf *rbuf=asfd->rbuf;
	const char *cname=get_string(cconfs[OPT_CNAME]);

	if(get_string(cconfs[OPT_SUPER_CLIENT]))
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
		int checkonly=!strncmp_w(rbuf->buf, "backupphase1timedcheck");
		if(checkonly) logp("Client asked for a timer check only.\n");

		if((*timer_ret=run_timer(asfd, sdirs, cconfs))<0)
		{
			logp("Error running timer for %s\n", cname);
			return -1;
		}
		else if(*timer_ret)
		{
			if(!checkonly)
				logp("Not running backup of %s\n", cname);
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

	if((bno_new=get_new_bno(sdirs))<0)
		return -1;
	if(get_string(cconfs[OPT_SEED_SRC])
	  && get_string(cconfs[OPT_SEED_DST])
	  && bno_new!=1)
	{
		log_and_send(asfd, "When seeding, there must be no previous backups for this client\n");
		return -1;
	}

	snprintf(okstr, sizeof(okstr), "%s:%d",
		resume?"resume":"ok", get_int(cconfs[OPT_COMPRESSION]));
	if(asfd->write_str(asfd, CMD_GEN, okstr)) return -1;

	if((ret=do_backup_server(as, sdirs, cconfs, incexc, resume, bno_new)))
		goto end;

	if((ret=delete_backups(sdirs, cname,
		get_strlist(cconfs[OPT_KEEP]),
		get_string(cconfs[OPT_MANUAL_DELETE]))))
			goto end;
end:
	return ret;
}
