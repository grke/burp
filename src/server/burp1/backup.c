#include "include.h"
#include "../backup_phase1.h"

#include <librsync.h>
#include <math.h>

/* Need to base librsync block length on the size of the old file, otherwise
   the risk of librsync collisions and silent corruption increases as the
   size of the new file gets bigger. */
size_t get_librsync_block_len(const char *endfile)
{
	size_t ret=0;
	unsigned long long oldlen=0;
	oldlen=strtoull(endfile, NULL, 10);
	ret=(size_t)(ceil(sqrt(oldlen)/16)*16); // round to a multiple of 16.
	if(ret<64) return 64; // minimum of 64 bytes.
	return ret;
}

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

static int vss_opts_changed(struct sdirs *sdirs, struct conf *cconf,
	const char *incexc)
{
	int ret=0;
	struct conf oldconf;
	struct conf newconf;
	conf_init(&oldconf);
	conf_init(&newconf);

	// Figure out the old config, which is in the incexc file left
	// in the current backup directory on the server.
	if(parse_incexcs_path(&oldconf, sdirs->cincexc))
	{
		// Assume that the file did not exist, and therefore
		// the old split_vss setting is 0.
		oldconf.split_vss=0;
		oldconf.strip_vss=0;
	}

	// Figure out the new config, which is either in the incexc file from
	// the client, or in the cconf on the server.
	if(incexc)
	{
		if(parse_incexcs_buf(&newconf, incexc))
		{
			// Should probably not got here.
			newconf.split_vss=0;
			newconf.strip_vss=0;
		}
	}
	else
	{
		newconf.split_vss=cconf->split_vss;
		newconf.strip_vss=cconf->strip_vss;
	}

	if(newconf.split_vss!=oldconf.split_vss)
	{
		logp("split_vss=%d (changed since last backup)\n",
			newconf.split_vss);
		ret=1;
	}
	if(newconf.strip_vss!=oldconf.strip_vss)
	{
		logp("strip_vss=%d (changed since last backup)\n",
			newconf.strip_vss);
		ret=1;
	}
	if(ret) logp("All files will be treated as new\n");
	return ret;
}

int do_backup_server_burp1(struct async *as,
	struct sdirs *sdirs, struct conf *cconf,
	const char *incexc, int resume)
{
	int ret=0;
	char msg[256]="";
	gzFile mzp=NULL;
	// Real path to the working directory
	char *realworking=NULL;
	char tstmp[64]="";
	struct asfd *asfd=as->asfd;

	struct dpthl dpthl;

	gzFile cmanfp=NULL;
	struct stat statp;

	logp("in do_backup_server\n");

	if(init_dpthl(&dpthl, asfd, sdirs, cconf))
	{
		log_and_send(asfd, "could not init_dpthl\n");
		goto error;
	}

	if(resume)
	{
		ssize_t len=0;
		char real[256]="";
		if((len=readlink(sdirs->working, real, sizeof(real)-1))<0)
			len=0;
		real[len]='\0';
		if(!(realworking=prepend_s(sdirs->client, real)))
		{
			log_and_send_oom(asfd, __func__);
			goto error;
		}
		if(open_log(asfd, realworking, cconf)) goto error;
	}
	else
	{
		// Not resuming - need to set everything up fresh.

		if(timestamp_get_new(asfd, sdirs, cconf, tstmp, sizeof(tstmp)))
			goto error;
		if(!(realworking=prepend_s(sdirs->client, tstmp)))
		{
			log_and_send_oom(asfd, __func__);
			goto error;
		}
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
			log_and_send(asfd, msg);
			goto error;
		}
		else if(mkdir(realworking, 0777))
		{
			snprintf(msg, sizeof(msg),
				"could not mkdir for next backup: %s",
				sdirs->working);
			log_and_send(asfd, msg);
			unlink(sdirs->working);
			goto error;
		}
		else if(open_log(asfd, realworking, cconf))
		{
			goto error;
		}
		else if(mkdir(sdirs->datadirtmp, 0777))
		{
			snprintf(msg, sizeof(msg),
			  "could not mkdir for datadir: %s", sdirs->datadirtmp);
			log_and_send(asfd, msg);
			goto error;
		}
		else if(timestamp_write(sdirs->timestamp, tstmp))
		{
			snprintf(msg, sizeof(msg),
			  "unable to write timestamp %s", sdirs->timestamp);
			log_and_send(asfd, msg);
			goto error;
		}
		else if(incexc && *incexc && write_incexc(realworking, incexc))
		{
			snprintf(msg, sizeof(msg), "unable to write incexc");
			log_and_send(asfd, msg);
			goto error;
		}

		if(backup_phase1_server(asfd, sdirs, cconf))
		{
			logp("error in phase 1\n");
			goto error;
		}
	}

	// Open the previous (current) manifest.
	// If the split_vss setting changed between the previous backup
	// and the new backup, do not open the previous manifest.
	// This will have the effect of making the client back up everything
	// fresh. Need to do this, otherwise toggling split_vss on and off
	// will result in backups that do not work.
	if(!lstat(sdirs->cmanifest, &statp)
	  && !vss_opts_changed(sdirs, cconf, incexc))
	{
		if(!(cmanfp=gzopen_file(sdirs->cmanifest, "rb")))
		{
			if(!lstat(sdirs->cmanifest, &statp))
			{
				logp("could not open old manifest %s\n",
					sdirs->cmanifest);
				goto error;
			}
		}
	}

	//if(cmanfp) logp("Current manifest: %s\n", sdirs->cmanifest);

	if(backup_phase2_server(asfd, sdirs, cconf, &cmanfp, &dpthl, resume))
	{
		logp("error in backup phase 2\n");
		goto error;
	}

	if(backup_phase3_server(sdirs, cconf,
		0 /* not recovery mode */, 1 /* compress */))
	{
		logp("error in backup phase 3\n");
		goto error;
	}

	// will not write anything more to
	// the new manifest
	// finish_backup will open it again
	// for reading
	if(gzclose_fp(&mzp))
	{
		logp("Error closing manifest after phase3\n");
		goto error;
	}

	asfd->write_str(asfd, CMD_GEN, "okbackupend");
	logp("Backup ending - disconnect from client.\n");

	// Close the connection with the client, the rest of the job
	// we can do by ourselves.
	asfd_close(as->asfd);

	// Move the symlink to indicate that we are now in the end
	// phase. 
	// The rename() race condition is automatically recoverable here.
	if(do_rename(sdirs->working, sdirs->finishing))
		goto error;

	set_logfp(NULL, cconf); // does an fclose on logfp.
	// finish_backup will open logfp again
	ret=backup_phase4_server(sdirs, cconf);
	if(!ret && cconf->keep>0) ret=delete_backups(asfd, sdirs, cconf);

	goto end;
error:
	ret=-1;
end:
	gzclose_fp(&cmanfp);
	gzclose_fp(&mzp);
	set_logfp(NULL, cconf); // does an fclose on logfp.
	return ret;
}
