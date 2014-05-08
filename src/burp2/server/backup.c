#include "include.h"
#include "champ_chooser/include.h"

static int write_incexc(const char *realworking, const char *incexc)
{
	int ret=-1;
	FILE *fp=NULL;
	char *path=NULL;
	if(!(path=prepend_s(realworking, "incexc")))
		goto end;
	if(!(fp=open_file(path, "wb")))
		goto end;
	fprintf(fp, "%s", incexc);
	ret=0;
end:
	if(close_fp(&fp))
	{
		logp("error writing to %s in write_incexc\n", path);
		ret=-1;
	}
	if(path) free(path);
	return ret;
}

// Used by the burp1 stuff.
int open_log(struct async *as, const char *realworking, struct conf *cconf)
{
	char *logpath=NULL;

	if(!(logpath=prepend_s(realworking, "log")))
	{
		log_and_send_oom(as, __func__);
		return -1;
	}
	if(set_logfp(logpath, cconf))
	{
		char msg[256]="";
		snprintf(msg, sizeof(msg),
			"could not open log file: %s", logpath);
		log_and_send(as, msg);
		free(logpath);
		return -1;
	}
	free(logpath);

	logp("Client version: %s\n", cconf->peer_version?:"");
	logp("Protocol: %d\n", cconf->protocol);
	// Make sure a warning appears in the backup log.
	// The client will already have been sent a message with logw.
	// This time, prevent it sending a logw to the client by specifying
	// NULL for cntr.
	if(cconf->version_warn) version_warn(as, NULL, cconf);

	return 0;
}

// Clean mess left over from a previously interrupted backup.
static int clean_rubble(struct async *as, struct sdirs *sdirs)
{
	int len=0;
	char *real=NULL;
	char lnk[32]="";
	if((len=readlink(sdirs->working, lnk, sizeof(lnk)-1))<0)
		return 0;
	else if(!len)
	{
		unlink(sdirs->working);
		return 0;
	}
	lnk[len]='\0';
	if(!(real=prepend_s(sdirs->client, lnk)))
	{
		log_and_send_oom(as, __func__);
		return -1;
	}
	if(recursive_delete(real, "", 1))
	{
		char msg[256]="";
		snprintf(msg, sizeof(msg), "Could not remove interrupted directory: %s", real);
		log_and_send(as, msg);
		return -1;
	}
	unlink(sdirs->working);
	return 0;
}

static struct async *setup_champ_chooser(struct sdirs *sdirs, struct conf *conf)
{
	int champsock=-1;
	char *champname=NULL;
	struct async *chas=NULL;

	// Connect to champ chooser now.
	// This may start up a new champ chooser. On a machine with multiple
	// cores, it may be faster to do now, way before it is actually needed
	// in phase2.
	if((champsock=connect_to_champ_chooser(sdirs, conf))<0)
	{
		logp("could not connect to champ chooser\n");
		goto error;
	}

	if(!(chas=async_alloc())
	  || chas->init(chas, champsock, NULL /* no SSL */, conf, 0))
		goto error;

	if(!(champname=prepend("cname",
		conf->cname, strlen(conf->cname), ":")))
			goto error;

	if(chas->write_str(chas, CMD_GEN, champname)
	  || chas->read_expect(chas, CMD_GEN, "cname ok"))
		goto error;

	free(champname);
	return chas;
error:
	free(champname);
	async_free(&chas);
	close_fd(&champsock);
	return NULL;
}

int do_backup_server(struct async **as, struct sdirs *sdirs,
	struct conf *cconf, const char *incexc, int resume)
{
	int ret=0;
	char msg[256]="";
	// Real path to the working directory
	char *realworking=NULL;
	// Real path to the manifest directory
	char *manifest_dir=NULL;
	char tstmp[64]="";
	struct async *chas=NULL;

	logp("in do_backup_server\n");

	if(get_new_timestamp(*as, sdirs, cconf, tstmp, sizeof(tstmp)))
		goto error;
	if(!(realworking=prepend_s(sdirs->client, tstmp))
	 || !(manifest_dir=prepend_s(realworking, "manifest")))
	{
		log_and_send_oom(*as, __func__);
		goto error;
	}

	if(clean_rubble(*as, sdirs)) goto error;

	// Add the working symlink before creating the directory.
	// This is because bedup checks the working symlink before
	// going into a directory. If the directory got created first,
	// bedup might go into it in the moment before the symlink
	// gets added.
	if(symlink(tstmp, sdirs->working)) // relative link to the real work dir
	{
		snprintf(msg, sizeof(msg),
		  "could not point working symlink to: %s",
		  realworking);
		log_and_send(*as, msg);
		goto error;
	}
	else if(mkdir(realworking, 0777))
	{
		snprintf(msg, sizeof(msg),
		  "could not mkdir for next backup: %s", sdirs->working);
		log_and_send(*as, msg);
		unlink(sdirs->working);
		goto error;
	}
	else if(open_log(*as, realworking, cconf))
	{
		goto error;
	}
	else if(write_timestamp(sdirs->timestamp, tstmp))
	{
		snprintf(msg, sizeof(msg),
		  "unable to write timestamp %s", sdirs->timestamp);
		log_and_send(*as, msg);
		goto error;
	}
	else if(incexc && *incexc && write_incexc(realworking, incexc))
	{
		snprintf(msg, sizeof(msg), "unable to write incexc");
		log_and_send(*as, msg);
		goto error;
	}

	if(!(chas=setup_champ_chooser(sdirs, cconf)))
	{
		log_and_send(*as, "problem connecting to champ chooser");
		goto error;
	}

	if(backup_phase1_server(*as, sdirs, cconf))
	{
		logp("error in phase1\n");
		goto error;
	}

	if(backup_phase2_server(*as, sdirs, manifest_dir, chas, resume, cconf))
	{
		logp("error in phase2\n");
		goto error;
	}

	// Close the connection with the client, the rest of the job
	// we can do by ourselves.
	async_free(as);

	if(backup_phase3_server(sdirs, manifest_dir, cconf))
	{
		logp("error in phase3\n");
		goto end;
	}

	cntr_stats_to_file(cconf->cntr, sdirs->working, ACTION_BACKUP);

	// Move the symlink to indicate that we are now finished.
	if(do_rename(sdirs->working, sdirs->current)) goto error;

	cntr_print(cconf->cntr, ACTION_BACKUP);

	logp("Backup completed.\n");

	set_logfp(NULL, cconf); // does an fclose on logfp.
	compress_filename(sdirs->current, "log", "log.gz", cconf);

	if(cconf->keep>0)
	{
		//ret=remove_old_backups(sdirs, cconf);
		// FIX THIS: Need to figure out which data files can be
		// deleted.
	}

	goto end;
error:
	ret=-1;
end:
	set_logfp(NULL, cconf);
	if(manifest_dir) free(manifest_dir);
	if(realworking) free(realworking);
	async_free(&chas);
	return ret;
}
