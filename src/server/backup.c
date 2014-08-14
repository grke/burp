#include "include.h"

#include "burp1/backup_phase2.h"
#include "burp1/backup_phase3.h"
#include "burp1/backup_phase4.h"
#include "burp2/backup_phase2.h"
#include "burp2/backup_phase3.h"
#include "burp2/champ_chooser/champ_client.h"

static int open_log(struct asfd *asfd, struct sdirs *sdirs, struct conf *cconf)
{
	int ret=-1;
	char *logpath=NULL;

	if(!(logpath=prepend_s(sdirs->rworking, "log"))) goto end;
	if(set_logfp(logpath, cconf))
	{
		logp("could not open log file: %s\n", logpath);
		goto end;
	}

	logp("Client version: %s\n", cconf->peer_version?:"");
	logp("Protocol: %d\n", cconf->protocol);
	if(cconf->client_is_windows)
		logp("Client is Windows\n");

	// Make sure a warning appears in the backup log.
	// The client will already have been sent a message with logw.
	// This time, prevent it sending a logw to the client by specifying
	// NULL for cntr.
	if(cconf->version_warn) version_warn(asfd, NULL, cconf);

	ret=0;
end:
	free_w(&logpath);
	return ret;
}

static int write_incexc(const char *realworking, const char *incexc)
{
	int ret=-1;
	FILE *fp=NULL;
	char *path=NULL;
	if(!incexc || !*incexc) return 0;
	if(!(path=prepend_s(realworking, "incexc"))
	  || !(fp=open_file(path, "wb")))
		goto end;
	fprintf(fp, "%s", incexc);
	ret=0;
end:
	if(close_fp(&fp))
	{
		logp("error writing to %s in write_incexc\n", path);
		ret=-1;
	}
	free_w(&path);
	return ret;
}

int backup_phase1_server(struct async *as,
	struct sdirs *sdirs, struct conf *cconf)
{
	return backup_phase1_server_all(as, sdirs, cconf);
}

int backup_phase2_server(struct async *as, struct sdirs *sdirs,
        const char *incexc, int resume, struct conf *cconf)
{
	switch(cconf->protocol)
	{
		case PROTO_BURP1:
			return backup_phase2_server_burp1(as, sdirs,
        			incexc, resume, cconf);
		default:
			return backup_phase2_server_burp2(as, sdirs,
        			resume, cconf);
	}
}

int backup_phase3_server(struct sdirs *sdirs,
	struct conf *cconf, int recovery, int compress)
{
	switch(cconf->protocol)
	{
		case PROTO_BURP1:
			return backup_phase3_server_burp1(sdirs,
				recovery, compress, cconf);
		default:
			return backup_phase3_server_burp2(sdirs, cconf);
	}
}

int backup_phase4_server(struct sdirs *sdirs, struct conf *cconf)
{
	switch(cconf->protocol)
	{
		case PROTO_BURP1:
			set_logfp(NULL, cconf);
			// Phase4 will open logfp again (in case it is
			// resuming).
			return backup_phase4_server_burp1(sdirs, cconf);
		default:
			logp("Phase4 is for burp1 only!\n");
			return -1;
	}
}

static int do_backup_server(struct async *as, struct sdirs *sdirs,
	struct conf *cconf, const char *incexc, int resume)
{
	int ret=0;
	struct asfd *chfd=NULL;
	struct asfd *asfd=as->asfd;

	logp("in do_backup_server\n");

	if(resume)
	{
		if(sdirs_get_real_working_from_symlink(sdirs, cconf)
		  || open_log(asfd, sdirs, cconf))
			goto error;
	}
	else
	{
		// Not resuming - need to set everything up fresh.
		if(sdirs_create_real_working(sdirs, cconf)
		  || sdirs_get_real_manifest(sdirs, cconf)
		  || open_log(asfd, sdirs, cconf))
			goto error;

		if(write_incexc(sdirs->rworking, incexc))
		{
			logp("unable to write incexc\n");
			goto error;
		}

		if(cconf->protocol==PROTO_BURP2
		  && !(chfd=champ_chooser_connect(as, sdirs, cconf)))
		{
			logp("problem connecting to champ chooser\n");
			goto error;
		}

		if(backup_phase1_server(as, sdirs, cconf))
		{
			logp("error in phase 1\n");
			goto error;
		}
	}

	if(backup_phase2_server(as, sdirs, incexc, resume, cconf))
	{
		logp("error in backup phase 2\n");
		goto error;
	}

	asfd->write_str(asfd, CMD_GEN, "okbackupend");

	// Close the connection with the client, the rest of the job we can do
	// by ourselves.
	logp("Backup ending - disconnect from client.\n");
	as->asfd_remove(as, asfd);
	asfd_close(asfd);

	if(backup_phase3_server(sdirs, cconf,
		0 /* not recovery mode */, 1 /* compress */))
	{
		logp("error in backup phase 3\n");
		goto error;
	}

	if(cconf->protocol==PROTO_BURP1)
	{
		if(do_rename(sdirs->working, sdirs->finishing))
			goto error;
		if(backup_phase4_server(sdirs, cconf))
		{
			logp("error in backup phase 4\n");
			goto error;
		}
	}

        cntr_print(cconf->cntr, ACTION_BACKUP);
	cntr_stats_to_file(cconf->cntr, sdirs->rworking, ACTION_BACKUP);

	if(cconf->protocol==PROTO_BURP1)
	{
		// Move the symlink to indicate that we are now in the end
		// phase. The rename() race condition is automatically
		// recoverable here.
		if(do_rename(sdirs->finishing, sdirs->current)) goto error;
	}
	else
	{
		// FIX THIS: check whether the race condition here means that
		// the backup is not automatically recoverable.
		if(do_rename(sdirs->working, sdirs->current)) goto error;
	}

        logp("Backup completed.\n");
	set_logfp(NULL, cconf);
        compress_filename(sdirs->rworking, "log", "log.gz", cconf);

	goto end;
error:
	ret=-1;
end:
	set_logfp(NULL, cconf);
        if(chfd) as->asfd_remove(as, chfd);
        asfd_free(&chfd);

	if(!ret && cconf->keep>0)
	{
		if(cconf->protocol==PROTO_BURP1)
		{
			delete_backups(sdirs, cconf);
		}
		else
		{
			// FIX THIS: Need to figure out which data files can be
			// deleted.
		}
	}
	return ret;
}

int run_backup(struct async *as, struct sdirs *sdirs, struct conf *cconf,
	const char *incexc, int *timer_ret, int resume)
{
	char okstr[32]="";
	struct asfd *asfd=as->asfd;
	struct iobuf *rbuf=asfd->rbuf;

	if(cconf->restore_client)
	{
		// This client is not the original client, so a backup might
		// cause all sorts of trouble.
		logp("Not allowing backup of %s\n", cconf->cname);
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

		args[a++]=cconf->timer_script;
		args[a++]=cconf->cname;
		args[a++]=sdirs->current;
		args[a++]=sdirs->client;
		args[a++]="reserved1";
		args[a++]="reserved2";
		args[a++]=NULL;
		if((*timer_ret=run_script(asfd, args,
		  cconf->timer_arg,
		  cconf,
		  1 /* wait */,
		  1 /* use logp */,
		  0 /* no logw */
		))<0)
		{
			logp("Error running timer script for %s\n",
				cconf->cname);
			return *timer_ret;
		}
		if(*timer_ret)
		{
			if(!checkonly)
				logp("Not running backup of %s\n",
					cconf->cname);
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
		logp("Running backup of %s\n", cconf->cname);
	}
	else if(!(cconf->client_can & CLIENT_CAN_FORCE_BACKUP))
	{
		logp("Not allowing forced backup of %s\n", cconf->cname);
		return asfd->write_str(asfd,
			CMD_GEN, "Forced backup is not allowed");
	}

	snprintf(okstr, sizeof(okstr), "%s:%d",
		resume?"resume":"ok", cconf->compression);
	if(asfd->write_str(asfd, CMD_GEN, okstr)) return -1;

	return do_backup_server(as, sdirs, cconf, incexc, resume);
}
