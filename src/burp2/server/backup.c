#include "include.h"

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
int open_log(const char *realworking, struct conf *cconf)
{
	char *logpath=NULL;

	if(!(logpath=prepend_s(realworking, "log")))
	{
		log_and_send_oom(__FUNCTION__);
		return -1;
	}
	if(set_logfp(logpath, cconf))
	{
		char msg[256]="";
		snprintf(msg, sizeof(msg),
				"could not open log file: %s", logpath);
		log_and_send(msg);
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
	if(cconf->version_warn) version_warn(NULL, cconf);

	return 0;
}

// Clean mess left over from a previously interrupted backup.
static int clean_rubble(struct sdirs *sdirs)
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
		log_and_send_oom(__FUNCTION__);
		return -1;
	}
	if(recursive_delete(real, "", 1))
	{
		char msg[256]="";
		snprintf(msg, sizeof(msg), "Could not remove interrupted directory: %s", real);
		log_and_send(msg);
		return -1;
	}
	unlink(sdirs->working);
	return 0;
}

#include <sys/un.h>

static int champ_chooser_accept(int s, struct conf *conf)
{
	int s2;
	socklen_t t;
	struct sockaddr_un remote;
	printf("Waiting for a connection...\n");
	t=sizeof(remote);
	if((s2=accept(s, (struct sockaddr *)&remote, &t))<0)
	{
		logp("accept error in %s: %s\n",
			__FUNCTION__, strerror(errno));
		return -1;
	}

	printf("Connected.\n");

	close_fd(&s2);
	return 0;
}

static int champ_chooser_child(struct sdirs *sdirs, struct conf *cconf)
{
	int s;
	int len;
	int ret;
	struct sockaddr_un local;

	printf("%d: champ child\n", getpid());

	if((s=socket(AF_UNIX, SOCK_STREAM, 0))<0)
	{
		logp("socket error in %s: %s\n",
			__FUNCTION__, strerror(errno));
		return -1;
	}

	local.sun_family=AF_UNIX;
	strcpy(local.sun_path, sdirs->champsock);
	unlink(local.sun_path);
	len=strlen(local.sun_path)+sizeof(local.sun_family);
	if(bind(s, (struct sockaddr *)&local, len)<0)
	{
		logp("bind error in %s: %s\n",
			__FUNCTION__, strerror(errno));
		return -1;
	}

	if(listen(s, cconf->max_children)<0)
	{
		logp("listen error in %s: %s\n",
			__FUNCTION__, strerror(errno));
		return -1;
	}

	while(1)
	{
		// Just do one connection for now.
		ret=champ_chooser_accept(s, cconf);
		break;
	}
	close_fd(&s);
	unlink(sdirs->champsock);
	return ret;
}

static int champ_chooser_fork(struct sdirs *sdirs, struct conf *cconf)
{
	pid_t childpid=-1;

	switch((childpid=fork()))
	{
		case -1:
			logp("fork failed in %s: %s\n",
				__FUNCTION__, strerror(errno));
			return -1;
		case 0:
			// Child.
			set_logfp(NULL, cconf);
			switch(champ_chooser_child(sdirs, cconf))
			{
				case 0: exit(0);
				default: exit(1);
			}
		default:
			// Parent.
			logp("forked champ chooser pid %d\n", childpid);
			return 0;
	}
}

static int connect_to_champ_chooser(struct sdirs *sdirs, struct conf *cconf)
{
	int len;
	int s=-1;
	int tries=0;
	int tries_max=3;
	struct sockaddr_un remote;

	if((s=socket(AF_UNIX, SOCK_STREAM, 0))<0)
	{
		logp("socket error in %s: %s\n",
			__FUNCTION__, strerror(errno));
		return -1;
	}

	printf("Trying to connect...\n");

	remote.sun_family=AF_UNIX;
	strcpy(remote.sun_path, sdirs->champsock);
	len=strlen(remote.sun_path)+sizeof(remote.sun_family);

	while(tries++<tries_max)
	{
		int sleeptimeleft=3;
		if(connect(s, (struct sockaddr *)&remote, len)<0)
		{
			if(errno==ENOENT)
			{
				// Path did not exist.
				// Try to fork a new champ chooser process and
				// try again.
				logp("Champ chooser socket does not exist.\n");
				if(champ_chooser_fork(sdirs, cconf)) break;
			}
			else
			{
				logp("connect error in %s: %d %s\n",
					__FUNCTION__, errno, strerror(errno));
			}
		}
		else
		{
			logp("Connected to champ chooser.\n");
			return s;
		}

		// SIGCHLDs may be interrupting.
		sleeptimeleft=3;
		while(sleeptimeleft>0) sleeptimeleft=sleep(sleeptimeleft);
	}

	logp("Could not connect to champ chooser via %s after %d attempts.",
		sdirs->champsock, tries);

	return -1;
}

int do_backup_server(struct sdirs *sdirs, struct conf *cconf,
	const char *incexc, int resume)
{
	int ret=0;
	int champsock=-1;
	char msg[256]="";
	// Real path to the working directory
	char *realworking=NULL;
	// Real path to the manifest directory
	char *manifest_dir=NULL;
	char tstmp[64]="";

	logp("in do_backup_server\n");

	if(get_new_timestamp(sdirs, cconf, tstmp, sizeof(tstmp)))
		goto error;
	if(!(realworking=prepend_s(sdirs->client, tstmp))
	 || !(manifest_dir=prepend_s(realworking, "manifest")))
	{
		log_and_send_oom(__FUNCTION__);
		goto error;
	}

	if(clean_rubble(sdirs)) goto error;

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
		log_and_send(msg);
		goto error;
	}
	else if(mkdir(realworking, 0777))
	{
		snprintf(msg, sizeof(msg),
		  "could not mkdir for next backup: %s", sdirs->working);
		log_and_send(msg);
		unlink(sdirs->working);
		goto error;
	}
	else if(open_log(realworking, cconf))
	{
		goto error;
	}
	else if(write_timestamp(sdirs->timestamp, tstmp))
	{
		snprintf(msg, sizeof(msg),
		  "unable to write timestamp %s", sdirs->timestamp);
		log_and_send(msg);
		goto error;
	}
	else if(incexc && *incexc && write_incexc(realworking, incexc))
	{
		snprintf(msg, sizeof(msg), "unable to write incexc");
		log_and_send(msg);
		goto error;
	}

	// Connect to champ chooser now.
	// This may start up a new champ chooser. On a machine with multiple
	// cores, it may be faster to do now, way before it is actually needed
	// in phase2.
	if((champsock=connect_to_champ_chooser(sdirs, cconf))<0)
	{
		snprintf(msg, sizeof(msg),
			"could not connect to champ chooser");
		log_and_send(msg);
		goto error;
	}

	if(backup_phase1_server(sdirs, cconf))
	{
		logp("error in phase1\n");
		goto error;
	}

	if(backup_phase2_server(sdirs, manifest_dir, champsock, resume, cconf))
	{
		logp("error in phase2\n");
		goto error;
	}

	// Close the connection with the client, the rest of the job
	// we can do by ourselves.
	async_free();

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
	close_fd(&champsock);
	return ret;
}
