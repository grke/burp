#include "burp.h"
#include "prog.h"
#include "msg.h"
#include "lock.h"
#include "rs_buf.h"
#include "handy.h"
#include "asyncio.h"
#include "zlibio.h"
#include "counter.h"
#include "dpth.h"
#include "sbuf.h"
#include "auth_server.h"
#include "backup_phase1_server.h"
#include "backup_phase2_server.h"
#include "backup_phase3_server.h"
#include "backup_phase4_server.h"
#include "current_backups_server.h"
#include "list_server.h"
#include "restore_server.h"
#include "ssl.h"
#include "berrno.h"
#include "status_server.h"
#include "forkchild.h"

#include <netdb.h>
#include <librsync.h>

static int sfd=-1; // status fd for the main server

static void sighandler(int sig)
{
	logp("got signal: %d\n", sig);
	// Close the sockets properly so as to attempt to avoid annoying waits
	// during testing when I kill the server with a Ctrl-C and then get
	// 'unable to bind listening socket'.
	async_free();
	close_fd(&sfd);
	close_fd(&status_wfd);
	close_fd(&status_rfd);
	logp("exiting\n");
	exit(1);
}

static int init_listen_socket(const char *port, int alladdr)
{
	int rfd;
	int gai_ret;
	struct addrinfo hints;
	struct addrinfo *result=NULL;
	struct addrinfo *rp=NULL;

	memset(&hints, 0, sizeof(struct addrinfo));
	hints.ai_family = AF_UNSPEC;
	hints.ai_socktype = SOCK_STREAM;
	hints.ai_flags = alladdr ? AI_PASSIVE : 0;
	hints.ai_protocol = IPPROTO_TCP;
	hints.ai_canonname = NULL;
	hints.ai_addr = NULL;
	hints.ai_next = NULL;

	if((gai_ret=getaddrinfo(NULL, port, &hints, &result)))
	{
		logp("unable to create listening socket on port %s: %s\n",
			port, gai_strerror(gai_ret));
		return -1;
	}

	for(rp=result; rp; rp=rp->ai_next)
	{
		rfd=socket(rp->ai_family, rp->ai_socktype, rp->ai_protocol);
		if(rfd<0) continue;
		if(!bind(rfd, rp->ai_addr, rp->ai_addrlen)) break;
		close(rfd);
	}
	freeaddrinfo(result);
	if(!rp)
	{
		logp("unable to bind listening socket on port %s\n", port);
		return -1;
	}

	reuseaddr(rfd);

	// Say that we are happy to accept connections.
	if(listen(rfd, 5)<0)
	{
		close_fd(&rfd);
		logp("could not listen on main socket %d\n", port);
		return -1;
	}

#ifdef HAVE_WIN32
	{
		u_long ioctlArg=0;
		ioctlsocket(rfd, FIONBIO, &ioctlArg);
	}
#endif

	return rfd;
}

// Structure that gives us data from forked children, in order to be able to
// give a 'live' status update.
// And can now also send data to forked status server children, to be able to
// write the 'live' status update to a status client.
// This also enables us to count the children in order to stay under the
// configured max_children limit.
struct chldstat
{
	pid_t pid;  // child pid
	int rfd;    // read end of the pipe from the child
	int wfd;    // write end of a different pipe to the child
	char *data; // last message sent from the child
	char *name; // client name
	int status_server; // set to 1 if this is a status server child.
};

// Want sigchld_handler to be able to access this, but you cannot pass any
// data into sigchld_handler, so it has to be a global.
static struct chldstat *chlds;

static void chldstat_free(struct chldstat *chld)
{
	chld->pid=-1;
	if(chld->data)
	{
		free(chld->data);
		chld->data=NULL;
	}
	if(chld->name)
	{
		free(chld->name);
		chld->name=NULL;
	}
	close_fd(&(chld->rfd));
	close_fd(&(chld->wfd));
}

// Remove any exiting child pids from our list.
static void check_for_exiting_children(void)
{
	pid_t p;
	int status;
	if((p=waitpid(-1, &status, WNOHANG))>0)
	{
		int q;
		logp("child pid %d exited\n", p);
		if(chlds) for(q=0; chlds[q].pid!=-2; q++)
		{
			if(p==chlds[q].pid)
			{
				//logp("removed %d from list\n", p);
				chldstat_free(&(chlds[q]));
				break;
			}
		}
	}
}

static void sigchld_handler(int sig)
{
	//printf("in sigchld_handler\n");
	check_for_exiting_children();
}

static void setup_signal(int sig, void handler(int sig))
{
	struct sigaction sa;
	memset(&sa, 0, sizeof(sa));
	sa.sa_handler=handler;
	sigaction(sig, &sa, NULL);
}

static int setup_signals(int max_children)
{
	// Ignore SIGPIPE - we are careful with read and write return values.
#ifndef HAVE_WIN32
	int p=0;
	struct sigaction sa;
	signal(SIGPIPE, SIG_IGN);
	// Get rid of defunct children.
	if(!(chlds=(struct chldstat *)
		malloc(sizeof(struct chldstat)*(max_children+1))))
	{
		logp("out of memory");
		return -1;
	}
	for(p=0; p<max_children+1; p++)
	{
		chlds[p].pid=-1;
		chlds[p].rfd=-1;
		chlds[p].wfd=-1;
		chlds[p].data=NULL;
		chlds[p].name=NULL;
		chlds[p].status_server=0;
	}
	// There is one extra entry in the list, as an 
	// end marker so that sigchld_handler does not fall
	// off the end of the array. Mark this one with pid=-2.
	chlds[max_children].pid=-2;

	memset(&sa, 0, sizeof(sa));
	sa.sa_handler=sigchld_handler;
	sigaction(SIGCHLD, &sa, NULL);

	setup_signal(SIGABRT, sighandler);
	setup_signal(SIGTERM, sighandler);
	setup_signal(SIGINT, sighandler);
#endif
	return 0;
}

static int do_backup_server(const char *basedir, const char *current, const char *working, const char *currentdata, const char *finishing, struct config *cconf, const char *manifest, const char *forward, const char *phase1data, const char *phase2data, const char *unchangeddata, const char *client, struct cntr *cntr)
{
	int ret=0;
	char msg[256]="";
	gzFile mzp=NULL;
	// The timestamp file of this backup
	char *timestamp=NULL;
	// Where the new file generated from the delta temporarily goes
	char *newpath=NULL;
	// path to the last manifest
	char *cmanifest=NULL;
	// Real path to the working directory
	char *realworking=NULL;
	char tstmp[64]="";
	char *datadirtmp=NULL;
	// Where to write messages
	char *logpath=NULL;
	FILE *logfp=NULL;
	// Where to write backupphase2 data.
	// Phase 2 data is not get written to a compressed file.
	// This is important for recovery if the power goes.
	FILE *p2fp=NULL;
	gzFile uczp=NULL;

	struct dpth dpth;

	gzFile cmanfp=NULL;
	struct stat statp;

	logp("in do_backup_server\n");

	if(!(timestamp=prepend_s(working, "timestamp", strlen("timestamp")))
	  || !(newpath=prepend_s(working, "patched.tmp", strlen("patched.tmp")))
	  || !(cmanifest=prepend_s(current, "manifest.gz", strlen("manifest.gz")))
	  || !(datadirtmp=prepend_s(working, "data.tmp", strlen("data.tmp"))))
	{
		log_and_send("out of memory");
		ret=-1;
	}
	else if(get_new_timestamp(basedir, tstmp, sizeof(tstmp)))
		ret=-1;
	else if(!(realworking=prepend_s(basedir, tstmp, strlen(tstmp)))
	  || !(logpath=prepend_s(realworking, "log", strlen("log"))))
	{
		log_and_send("out of memory");
		ret=-1;
	}
	else if(mkdir(realworking, 0777))
	{
		snprintf(msg, sizeof(msg),
		  "could not mkdir for increment: %s", working);
		log_and_send(msg);
		ret=-1;
	}
	else if(!(logfp=open_file(logpath, "ab")) || set_logfp(logfp))
	{
		snprintf(msg, sizeof(msg),
		  "could not open log file: %s", logpath);
		log_and_send(msg);
		ret=-1;
	}
	else if(symlink(tstmp, working)) // relative link to the real work dir
	{
		snprintf(msg, sizeof(msg),
		  "could not point working symlink to: %s", realworking);
		ret=-1;
	}
	else if(mkdir(datadirtmp, 0777))
	{
		snprintf(msg, sizeof(msg),
		  "could not mkdir for datadir: %s", datadirtmp);
		log_and_send(msg);
		ret=-1;
	}
	else if(write_timestamp(timestamp, tstmp))
	{
		snprintf(msg, sizeof(msg),
		  "unable to write timestamp %s", timestamp);
		log_and_send(msg);
		ret=-1;
	}
	if(!ret && init_dpth(&dpth, currentdata, cconf))
	{
		log_and_send("could not init_dpth\n");
		ret=-1;
	}

	if(!ret && backup_phase1_server(phase1data, client, cntr, cconf))
	{
		logp("error in backup phase 1\n");
		ret=-1;
	}

	// Open the previous (current) manifest.
	if(!ret && !lstat(cmanifest, &statp)
		&& !(cmanfp=gzopen_file(cmanifest, "rb")))
	{
		if(!lstat(cmanifest, &statp))
		{
			logp("could not open old manifest %s\n", cmanifest);
			ret=-1;
		}
	}

	//if(cmanfp) logp("Current manifest: %s\n", cmanifest);

	if(!ret && !(p2fp=open_file(phase2data, "wb")))
		ret=-1;
	if(!ret && !(uczp=gzopen_file(unchangeddata, comp_level(cconf))))
		ret=-1;
	if(!ret && backup_phase2_server(&cmanfp, phase1data, p2fp, uczp,
		datadirtmp, &dpth, currentdata, working, client, cntr, cconf))
	{
		logp("error in backup phase 2\n");
		ret=-1;
	}

	// Close the phase2, and unchanged files.
	// Phase3 will open phase2 and unchanged again, and combine them
	// into a new manifest.
	close_fp(&p2fp);
	gzclose_fp(&uczp);

	if(!ret && backup_phase3_server(phase2data, unchangeddata, manifest,
		0 /* not recovery mode */, 1 /* compress */, client, cntr,
		cconf))
	{
		logp("error in backup phase 3\n");
		ret=-1;
	}

	if(!ret)
	{
		// will not write anything more to
		// the new manifest
		// finish_backup will open it again
		// for reading
		gzclose_fp(&mzp);

		async_write_str(CMD_GEN, "okbackupend");
		logp("Backup ending - disconnect from client.\n");

		// Close the connection with the client, the rest of the job
		// we can do by ourselves.
		async_free();

		// Move the symlink to indicate that we are now in the end
		// phase. 
		if(do_rename(working, finishing))
			ret=-1;
		else
		{
			set_logfp(NULL); // does an fclose on logfp.
			// finish_backup will open logfp again
			ret=backup_phase4_server(basedir,
				working, current, currentdata,
				finishing, cconf, client, cntr);
			if(!ret && cconf->keep>0)
				ret=remove_old_backups(basedir, cconf->keep);
		}
	}
	gzclose_fp(&cmanfp);
	gzclose_fp(&mzp);
	close_fp(&p2fp);
	gzclose_fp(&uczp);
	if(timestamp) free(timestamp);
	if(newpath) free(newpath);
	if(cmanifest) free(cmanifest);
	if(datadirtmp) free(datadirtmp);
	if(logpath) free(logpath);
	set_logfp(NULL); // does an fclose on logfp.
	return ret;
}

static int maybe_rebuild_manifest(const char *phase2data, const char *unchangeddata, const char *manifest, int compress, const char *client, struct cntr *cntr, struct config *cconf)
{
	struct stat statp;
	if(!lstat(manifest, &statp))
	{
		unlink(phase2data);
		unlink(unchangeddata);
		return 0;
	}
	return backup_phase3_server(phase2data, unchangeddata, manifest,
		1 /* recovery mode */, compress, client, cntr, cconf);
}

static int check_for_rubble(const char *basedir, const char *current, const char *working, const char *currentdata, const char *finishing, struct config *cconf, const char *phase1data, const char *phase2data, const char *unchangeddata, const char *manifest, const char *client, struct cntr *cntr)
{
	size_t len=0;
	char realwork[256]="";
	struct stat statp;
	char *logpath=NULL;
	char *fullrealwork=NULL;
	FILE *logfp=NULL;
	char *phase1datatmp=NULL;
	const char *wdrm=cconf->working_dir_recovery_method;

	// If there is a 'finishing' symlink, we need to
	// run the finish_backup stuff.
	if(!lstat(finishing, &statp))
	{
		int r=0;
		logp("Found finishing symlink - attempting to complete prior backup!\n");
		r=backup_phase4_server(basedir,
			working,
			current,
			currentdata,
			finishing,
			cconf,
			client,
			cntr);
		if(!r) logp("Prior backup completed OK.\n");
		return r;
	}

	if(lstat(working, &statp))
	{
		// No working directory - that is good.
		return 0;
	}
	if(!S_ISLNK(statp.st_mode))
	{
		logp("Working directory is not a symlink.\n");
		return -1;
	}

	// The working directory has not finished being populated.
	// Check what to do.
	if((len=readlink(working, realwork, sizeof(realwork)-1))<0)
	{
		logp("Could not readlink on old working directory: %s\n", strerror(errno));
		return -1;
	}
	realwork[len]='\0';
	if(!(fullrealwork=prepend_s(basedir, realwork, strlen(realwork))))
		return -1;

	if(lstat(fullrealwork, &statp))
	{
		logp("could not lstat '%s' - something odd is going on\n",
			fullrealwork);
		free(fullrealwork);
		return -1;
	}

	if(!(phase1datatmp=get_tmp_filename(phase1data)))
	{
		free(fullrealwork);
		return -1;
	}

	// We have found an old working directory - open the log inside
	// for appending.
	if(!(logpath=prepend_s(fullrealwork, "log", strlen("log")))
	  || !(logfp=open_file(logpath, "ab")) || set_logfp(logfp))
	{
		free(fullrealwork);
		if(logpath) free(logpath);
		if(phase1datatmp) free(phase1datatmp);
		return -1;
	}
	free(logpath); logpath=NULL;

	logp("found old working directory: %s\n", fullrealwork);
	logp("working_dir_recovery_method: %s\n", wdrm);

	if(!lstat(phase1datatmp, &statp))
	{
		// Phase 1 did not complete - delete everything.
		logp("Phase 1 has not completed.\n");
		wdrm="delete";
	}
	free(phase1datatmp); phase1datatmp=NULL;

	if(!strcmp(wdrm, "delete"))
	{
		// Try to remove it and start again.
		logp("deleting old working directory\n");
		if(recursive_delete(fullrealwork,
			NULL, TRUE /* delete files */))
		{
			logp("Old working directory is in the way.\n");
			free(fullrealwork);
			set_logfp(NULL); // fclose the logfp
			return -1;
		}
		unlink(working); // get rid of the symlink.
	}
	else if(!strcmp(wdrm, "use"))
	{
		// Use it as it is.
		logp("converting old working directory into the latest backup\n");
		free(fullrealwork);

		// TODO: There might be a partial file written that is not
		// yet logged to the manifest. It does no harm other than
		// taking up some disk space. Detect this and remove it.

		// Get us a partial manifest from the files lying around.
		if(maybe_rebuild_manifest(phase2data, unchangeddata, manifest,
			1 /* compress */, client, cntr, cconf))
		{
			set_logfp(NULL); // fclose the logfp
			return -1;
		}

		// Now just rename the working link to be a finishing link,
		// then run this function again.
		if(do_rename(working, finishing))
		{
			set_logfp(NULL); // fclose the logfp
			return -1;
		}
		set_logfp(NULL); // fclose the logfp

		return check_for_rubble(basedir, current, working,
			currentdata, finishing, cconf, phase1data, phase2data,
			unchangeddata, manifest, client, cntr);
	}
	else if(!strcmp(wdrm, "merge"))
	{
		// Forward merge with the 'current' backup.
		// I had trouble re-opening a gz file for appending, so
		// the new manifest now starts out as a normal file.
		FILE *mp=NULL;
		gzFile czp=NULL;
		char *cmanifest=NULL;
		char *manifesttmp=NULL;

		logp("merging old working directory with the most recent backup\n");

		if(!(manifesttmp=get_tmp_filename(manifest))) return -1;

		logp("rebuild\n");
		// Get us a partial manifest from the files lying around.
		if(maybe_rebuild_manifest(phase2data, unchangeddata,
			manifesttmp, 0 /* do not compress */, client, cntr,
			cconf))
		{
			set_logfp(NULL); // fclose the logfp
			free(manifesttmp);
			return -1;
		}
		logp("after rebuild\n");

		// Open the partial manifest for appending.
		// Open the previous manifest for reading.
		// Forward through the previous manifest until at the
		// place where the partial one ended, then copy the rest of
		// the old one into the new one.

		free(fullrealwork);

		if(!(mp=open_file(manifesttmp, "r+b"))
		  || !(cmanifest=prepend_s(current,
			"manifest.gz", strlen("manifest.gz"))))
		{
			set_logfp(NULL); // fclose the logfp
			free(manifesttmp);
			return -1;
		}

		if((czp=gzopen_file(cmanifest, "rb")))
		{
			int ars=0;
			char *lastpbuf=NULL;
			z_off_t offz=0;
			struct sbuf pb;
			struct sbuf cb;

			init_sbuf(&pb);
			init_sbuf(&cb);

			// Forwarding through working manifest...
			while(1)
			{
			  int ars;
			  free_sbuf(&pb);
			  if((ars=sbuf_fill(mp, NULL, &pb, cntr))<0)
			  {
				free_sbuf(&pb);
				close_fp(&mp);
				gzclose_fp(&czp);
				free(cmanifest);
				free(manifesttmp);
				set_logfp(NULL); // fclose the logfp
				return -1;
			  }
			  if(ars==1) break; // got to the end

			  if(lastpbuf) free(lastpbuf);
			  lastpbuf=strdup(pb.path);
			  free_sbuf(&pb);
			}
			free_sbuf(&pb);

			// Now we should have the latest file entry.
			// Forward through the current manifest.

			if(lastpbuf)
			{
			 logp("Last path in working manifest: '%s'\n",
				lastpbuf);
			 while(1)
			 {
			  if((offz=gztell(czp))<0)
			  {
				logp("gztell returned error\n");
				free_sbuf(&pb);
				free_sbuf(&cb);
				close_fp(&mp);
				gzclose_fp(&czp);
				free(cmanifest);
				free(manifesttmp);
				free(lastpbuf);
				set_logfp(NULL); // fclose the logfp
				return -1;
			  }
			  free_sbuf(&cb);
			  if((ars=sbuf_fill(NULL, czp, &cb, cntr))<0)
			  {
				free_sbuf(&pb);
				free_sbuf(&cb);
				close_fp(&mp);
				gzclose_fp(&czp);
				free(cmanifest);
				free(manifesttmp);
				free(lastpbuf);
				set_logfp(NULL); // fclose the logfp
				return -1;
			  }
			  if(cb.path && pathcmp(lastpbuf, cb.path)<0)
			  {
				// Ahead in the current manifest.
				// Get back to the start of this entry.

				logp("Ahead in the current manifest\n");
				logp("working: %s\n", lastpbuf);
				logp("current: %s\n", cb.path);
				if(gzseek(czp, offz, SEEK_SET)!=offz)
				{
					logp("error in gzseek\n");
					free_sbuf(&pb);
					free_sbuf(&cb);
					close_fp(&mp);
					gzclose_fp(&czp);
					free(cmanifest);
					free(manifesttmp);
					free(lastpbuf);
					set_logfp(NULL); // fclose the logfp
					return -1;
				}
				break;
			  }
			  if(ars==1) break; // got to the end
			  free_sbuf(&pb);
			  free_sbuf(&cb);
			 }
			 free(lastpbuf);
			}
			else
			{
				logp("Did not find last path in working manifest.\n");
			}
			free_sbuf(&pb);
			free_sbuf(&cb);

			// Write the rest of the current manifest into
			// the working one.
			logp("Filling in working manifest...\n");
			while(1)
			{
				free_sbuf(&cb);
				if((ars=sbuf_fill(NULL, czp, &cb, cntr))<0)
				{
					close_fp(&mp);
					gzclose_fp(&czp);
					free(cmanifest);
					set_logfp(NULL); // fclose the logfp
					return -1;
				}
				else if(ars==1)
				{
					break; // finished
				}

				logp("sbuf to manifest\n");
				if(sbuf_to_manifest(&cb, mp, NULL))
				{
					close_fp(&mp);
					gzclose_fp(&czp);
					free(cmanifest);
					set_logfp(NULL); // fclose the logfp
					return -1;
				}

				free_sbuf(&cb);
			}
			close_fp(&mp);
			gzclose_fp(&czp);
			if(compress_file(manifesttmp, manifest, cconf))
			{
				logp("manifest compress failed\n");
				free(manifesttmp);
				return -1;
			}
			free(manifesttmp);
			logp("Merge OK\n");
		}
		else
		{
			logp("No current backup found.\n");
			logp("Will use old working directory as the current backup.\n");
		}
		free(cmanifest);

		// Then rename the working link to be a finishing link,
		// then run this function again.
		if(do_rename(working, finishing))
		{
			set_logfp(NULL); // fclose the logfp
			return -1;
		}
		set_logfp(NULL); // fclose the logfp

		return check_for_rubble(basedir, current, working,
			currentdata, finishing, cconf, phase1data, phase2data,
			unchangeddata, manifest, client, cntr);
	}
	else
	{
		logp("Unknown working_dir_recovery_method: %s\n", wdrm);
		free(fullrealwork);
		set_logfp(NULL); // fclose the logfp
		return -1;
	}

	free(fullrealwork);
	set_logfp(NULL); // fclose the logfp
	return 0;
}

static int get_lock_and_clean(const char *basedir, const char *lockfile, const char *current, const char *working, const char *currentdata, const char *finishing, bool cancel, bool *gotlock, struct config *cconf, const char *forward, const char *phase1data, const char *phase2data, const char *unchangeddata, const char *manifest, const char *client, struct cntr *cntr)
{
	int ret=0;
	char *copy=NULL;
	// Make sure the lock directory exists.
	if(!(copy=strdup(lockfile))
	  || mkpath(&copy))
	{
		async_write_str(CMD_ERROR, "problem with lock directory");
		if(copy) free(copy);
		return -1;
	}
	free(copy);

	if(get_lock(lockfile))
	{
		if(cancel)
		{
			struct stat statp;
			if(!lstat(finishing, &statp))
			{
				char msg[256]="";
				logp("finalising previous backup\n");
				snprintf(msg, sizeof(msg), "Finalising previous backup of client. Please try again later.");
				async_write_str(CMD_ERROR, msg);
			}
			else
			{
				logp("another instance of client is already running,\n");
				logp("or %s is not writable.\n", lockfile);
				async_write_str(CMD_ERROR, "another instance is already running");
			}
		}
		ret=-1;
	}
	else *gotlock=TRUE;

	if(!ret && check_for_rubble(basedir, current, working, currentdata,
		finishing, cconf, phase1data, phase2data, unchangeddata,
		manifest, client, cntr))
			ret=-1;

	return ret;
}

static int run_script_w(const char *script, struct strlist **userargs, int userargc, const char *client, const char *current, struct cntr *cntr)
{
	return run_script(script, userargs, userargc, client, current,
		"reserved1", "reserved2", "reserved3", cntr);
}

static int child(struct config *conf, struct config *cconf, const char *client)
{
	int ret=0;
	char cmd;
	char msg[256]="";
	char *buf=NULL;
	size_t len=0;
	char *basedir=NULL;
	// Do not allow a single client to connect more than once
	char *lockbasedir=NULL;
	char *lockfile=NULL;
	bool gotlock=FALSE;
	// The previous backup
	char *current=NULL;
	// The one we are working on
	char *working=NULL;
	// The full path to the latest backup data
	char *currentdata=NULL;
	// where the data goes initially
	char *datadirtmp=NULL;
	// File containing timestamp of the next backup in the sequence.
	char *forward=NULL;
	// The final compressed manifest 
	char *manifest=NULL;
	// A symlink that indicates that the
	// data from the client is complete and just some work on the server 
	// is needed to finish. The 'working' symlink gets renamed to this
	// at the appropriate moment.
	char *finishing=NULL;
	char *phase1data=NULL;
	char *phase2data=NULL;
	char *unchangeddata=NULL;
	struct cntr cntr;

	reset_filecounter(&cntr);

	if(!(basedir=prepend_s(cconf->directory, client, strlen(client)))
	  || !(working=prepend_s(basedir, "working", strlen("working")))
	  || !(finishing=prepend_s(basedir, "finishing", strlen("finishing")))
	  || !(current=prepend_s(basedir, "current", strlen("current")))
	  || !(currentdata=prepend_s(current, "data", strlen("data")))
	  || !(manifest=prepend_s(working, "manifest.gz", strlen("manifest.gz")))
	  || !(datadirtmp=prepend_s(working, "data.tmp", strlen("data.tmp")))
	  || !(phase1data=prepend_s(working, "phase1.gz", strlen("phase1.gz")))
	  || !(phase2data=prepend_s(working, "phase2", strlen("phase2")))
	  || !(unchangeddata=prepend_s(working, "unchanged", strlen("unchanged")))
	  || !(forward=prepend_s(current, "forward", strlen("forward")))
	  || !(lockbasedir=prepend_s(conf->client_lockdir, client, strlen(client)))
	  || !(lockfile=prepend_s(lockbasedir, "lockfile", strlen("lockfile"))))
	{
		log_and_send("out of memory");
		ret=-1;
	}
	else if(async_read(&cmd, &buf, &len))
	{
		ret=-1;
	}
	else if(cmd==CMD_GEN && !strncmp(buf, "backupphase1", strlen("backupphase1")))
	{
		if(get_lock_and_clean(basedir, lockfile, current,
			working, currentdata,
			finishing, TRUE, &gotlock, cconf,
			forward, phase1data, phase2data, unchangeddata,
			manifest, client, &cntr))
				ret=-1;
		else
		{
			int tret=0;
			char okstr[32]="ok";
			if(mkpath(&current)) // creates basedir, without the /current part
			{
				snprintf(msg, sizeof(msg), "could not mkpath %s", working);
				log_and_send(msg);
				ret=-1;
				goto end;
			}
			if(!strcmp(buf, "backupphase1timed"))
			{
				if((tret=run_script_w(
					cconf->timer_script,
					cconf->timer_arg,
					cconf->tacount,
					client, current, &cntr))<0)
				{
					ret=tret;
					logp("Error running timer script for %s\n", client);
					goto end;
				}
				if(tret)
				{
					logp("Not running backup of %s\n",
						client);
					async_write_str(CMD_GEN,
						"timer conditions not met");
					goto end;
				}
				logp("Running backup of %s\n", client);
			}
			free(buf); buf=NULL;

			snprintf(okstr, sizeof(okstr), "ok:%d",
				cconf->compression);
			async_write_str(CMD_GEN, okstr);
			ret=do_backup_server(basedir, current, working,
			  currentdata, finishing, cconf,
			  manifest, forward, phase1data, phase2data,
			  unchangeddata, client, &cntr);
			if(ret)
				run_script(
					cconf->notify_failure_script,
					cconf->notify_failure_arg,
					cconf->nfcount,
					client, current,
					working, finishing,
					"reserved", &cntr);
			else
				run_script(
					cconf->notify_success_script,
					cconf->notify_success_arg,
					cconf->nscount,
					client, current,
					working, finishing,
					"reserved", &cntr);
		}
	}
	else if(cmd==CMD_GEN
	  && (!strncmp(buf, "restore ", strlen("restore "))
		|| !strncmp(buf, "verify ", strlen("verify "))))
	{
		enum action act;
		char *backupnostr=NULL;
		// Hmm. inefficient.
	  	if(!strncmp(buf, "restore ", strlen("restore ")))
		{
			backupnostr=buf+strlen("restore ");
			act=ACTION_RESTORE;
		}
		else
		{
			backupnostr=buf+strlen("verify ");
			act=ACTION_VERIFY;
		}

		if(get_lock_and_clean(basedir, lockfile, current, working,
			currentdata, finishing, TRUE, &gotlock, cconf,
			forward, phase1data, phase2data, unchangeddata,
			manifest, client, &cntr))
				ret=-1;
		else
		{
			char *restoreregex=NULL;
			if((restoreregex=strrchr(buf, ':')))
			{
				*restoreregex='\0';
				restoreregex++;
			}
			async_write_str(CMD_GEN, "ok");
			ret=do_restore_server(basedir, backupnostr,
				restoreregex, act, client, &cntr, cconf);
		}
	}
	else if(cmd==CMD_GEN && !strncmp(buf, "list ", strlen("list ")))
	{
		if(get_lock_and_clean(basedir, lockfile, current, working,
			currentdata, finishing, FALSE, &gotlock, cconf,
			forward, phase1data, phase2data, unchangeddata,
			manifest, client, &cntr))
				ret=-1;
		else
		{
			char *listregex=NULL;
			if((listregex=strrchr(buf, ':')))
			{
				*listregex='\0';
				listregex++;
			}
			async_write_str(CMD_GEN, "ok");
			ret=do_list_server(basedir, buf+strlen("list "),
				listregex, client, &cntr);
		}
	}
	else
	{
		logp("unknown command: %c:%s\n", cmd, buf);
		async_write_str(CMD_ERROR, "unknown command");
		ret=-1;
	}

end:
	if(buf) free(buf);

	if(basedir) free(basedir);
	if(current) free(current);
	if(finishing) free(finishing);
	if(working) free(working);
	if(currentdata) free(currentdata);
	if(datadirtmp) free(datadirtmp);
	if(manifest) free(manifest);
	if(forward) free(forward);
	if(phase1data) free(phase1data);
	if(phase2data) free(phase2data);
	if(unchangeddata) free(unchangeddata);
	if(lockbasedir) free(lockbasedir);
	if(lockfile)
	{
		if(gotlock) unlink(lockfile);
		free(lockfile);
	}
	return ret;
}

#define KEYFILE "server.pem"
#define PASSWORD "password"
#define DHFILE "dh1024.pem"

static int run_child(int *rfd, int *cfd, SSL_CTX *ctx, const char *configfile, int forking)
{
	int ret=0;
	SSL *ssl=NULL;
	BIO *sbio=NULL;
	char *client=NULL;
	struct config conf;
	struct config cconf;

	if(forking) close_fd(rfd);

	// Reload global config, in case things have changed. This means that
	// the server does not need to be restarted for most config changes.
	init_config(&conf);
	if(load_config(configfile, &conf, 1)) return -1;

	if(!(sbio=BIO_new_socket(*cfd, BIO_NOCLOSE))
	  || !(ssl=SSL_new(ctx)))
	{
		logp("There was a problem joining ssl to the socket\n");
		close_fd(cfd);
		free_config(&conf);
		return -1;
	}
	SSL_set_bio(ssl, sbio, sbio);

	if((ret=SSL_accept(ssl))<=0)
	{
		logp("SSL_accept: %d\n", ret);
		berr_exit("SSL accept error");
		close_fd(cfd);
		free_config(&conf);
		return -1;
	}
	if(async_init(*cfd, ssl))
	{
		close_fd(cfd);
		free_config(&conf);
		return -1;
	}
	if(authorise_server(&conf, &client, &cconf) || !client || !*client)
	{
		// add an annoying delay in case they are tempted to
		// try repeatedly
		log_and_send("unable to authorise");
		sleep(1);
		close_fd(cfd);
		free_config(&conf);
		return -1;
	}
	// Now that the client conf is loaded, we might want to chuser or
	// chgrp.
	if(chuser_and_or_chgrp(cconf.user, cconf.group))
	{
		logp("chuser_and_or_chgrp failed\n");
		close_fd(cfd);
		if(client) free(client);
		free_config(&conf);
		free_config(&cconf);
		return -1;
	}
	if(ssl_check_cert(ssl, &cconf))
	{
		logp("check cert failed\n");
		close_fd(cfd);
		if(client) free(client);
		free_config(&conf);
		free_config(&cconf);
		return -1;
	}
	set_non_blocking(*cfd);

	ret=child(&conf, &cconf, client);

	*cfd=-1;
	async_free(); // this closes cfd for us.
	logp("exit child\n");
	if(client) free(client);
	free_config(&conf);
	free_config(&cconf);
	return ret;
}

static int run_status_server(int *rfd, int *cfd, const char *configfile)
{
	int ret=0;
	struct config conf;

	close_fd(rfd);

	// Reload global config, in case things have changed. This means that
	// the server does not need to be restarted for most config changes.
	init_config(&conf);
	if(load_config(configfile, &conf, 1)) return -1;

	ret=status_server(cfd, &conf);

	close_fd(cfd);

	logp("exit status server\n");

	free_config(&conf);

	return ret;
}

static int process_incoming_client(int rfd, int forking, struct config *conf, SSL_CTX *ctx, const char *configfile, int is_status_server)
{
	int cfd=-1;
	socklen_t client_length=0;
	struct sockaddr_in client_name;

	client_length=sizeof(client_name);
	if((cfd=accept(rfd,
		(struct sockaddr *) &client_name,
		&client_length))==-1)
	{
		// Look out, accept will get interrupted by SIGCHLDs.
		if(errno==EINTR) return 0;
		logp("accept failed on %d: %s\n", rfd, strerror(errno));
		return -1;
	}
	reuseaddr(cfd);
	check_for_exiting_children();

	if(forking)
	{
	  int p=0;
	  int pipe_rfd[2];
	  int pipe_wfd[2];
	  pid_t childpid;

	  // Find a spare slot in our pid list for the child.
	  for(p=0; p<conf->max_children; p++) if(chlds[p].pid<0) break;
	  if(p==conf->max_children)
	  {
		logp("Too many child processes. Closing new connection.\n");
		close_fd(&cfd);
		return 0;
	  }
	  if(pipe(pipe_rfd)<0
	    || pipe(pipe_wfd)<0)
	  {
		logp("pipe failed: %s", strerror(errno));
		close_fd(&cfd);
		return -1;
	  }
	  /* fork off our new process to handle this request */
	  switch((childpid=fork()))
	  {
		case -1:
			logp("fork failed: %s\n", strerror(errno));
			break;
		case 0:
		{
			int ret;
			// child
			struct sigaction sa;

			// Set SIGCHLD back to default, so that I
			// can get sensible returns from waitpid.
			memset(&sa, 0, sizeof(sa));
			sa.sa_handler=SIG_DFL;
			sigaction(SIGCHLD, &sa, NULL);

			close(pipe_rfd[0]); // close read end
			close(pipe_wfd[1]); // close write end

			free_config(conf);

			set_blocking(pipe_rfd[1]);
			status_wfd=pipe_rfd[1];
			status_rfd=pipe_wfd[0];

			if(is_status_server)
			  ret=run_status_server(&rfd, &cfd, configfile);
			else
			  ret=run_child(&rfd, &cfd, ctx, configfile, forking);
			close_fd(&status_wfd);
			close_fd(&status_rfd);
			exit(ret);
		}
		default:
			// parent
			close(pipe_rfd[1]); // close write end
			close(pipe_wfd[0]); // close read end

			// keep a note of the child pid.
			if(is_status_server)
				logp("forked status server child pid %d\n", childpid);
			else
				logp("forked child pid %d\n", childpid);
			chlds[p].pid=childpid;
			chlds[p].rfd=pipe_rfd[0];
			chlds[p].wfd=pipe_wfd[1];
			chlds[p].status_server=is_status_server;
			set_blocking(chlds[p].rfd);
			close_fd(&cfd);
			break;
	  }
	}
	else
	{
		//free_config(conf);
		if(is_status_server)
			return run_status_server(&rfd, &cfd, configfile);
		else
			return run_child(&rfd, &cfd, ctx, configfile, forking);
	}
	return 0;
}

static int daemonise(void)
{
	/* process ID */
	pid_t pid;

	/* session ID */
	pid_t sid;

	/* fork new child and end parent */
	pid=fork();

	/* did we fork? */
	if(pid<0)
	{
		logp("error forking\n");
		return -1;
	}

	/* parent? */
	if(pid>0)
		exit(EXIT_SUCCESS);

	/* now we are in the child process */

	/* create a session and set the process group ID */
	sid=setsid();
	if(sid<0)
	{
		logp("error setting sid\n");
		return -1;
	}

	/* leave and unblock current working dir */
	if(chdir("/")<0)
	{
		logp("error changing working dir\n");
		return -1;
	}

	/* close std* */
	close(STDIN_FILENO);
	close(STDOUT_FILENO);
	close(STDERR_FILENO);

	return 0;
}

static int relock(const char *lockfile)
{
	int tries=5;
	for(; tries>0; tries--)
	{
		if(!get_lock(lockfile)) return 0;
		sleep(2);
	}
	logp("Unable to re-get lockfile after forking.\n");
	return -1;
}

int server(struct config *conf, const char *configfile, int forking, int daemon)
{
	int ret=0;
	int rfd=-1; // normal client port
	SSL_CTX *ctx=NULL;

	if(forking && daemon)
	{
		if(daemonise() || relock(conf->lockfile)) return 1;
	}

	/* change umask */
	umask(conf->umask);

	setup_signals(conf->max_children);

	ssl_load_globals();

	if(!(ctx=ssl_initialise_ctx(conf)))
	{
		logp("error initialising ssl ctx\n");
		return 1;
	}
	if((ssl_load_dh_params(ctx, conf)))
	{
		logp("error loading dh params\n");
		return 1;
	}
	SSL_CTX_set_verify(ctx, SSL_VERIFY_PEER |
		SSL_VERIFY_FAIL_IF_NO_PEER_CERT,0);

	if((rfd=init_listen_socket(conf->port, 1))<0) return 1;
	if(conf->status_port
		&& (sfd=init_listen_socket(conf->status_port, 0))<0) return 1;

	//if(chuser_and_or_chgrp(conf->user, conf->group))
	//	return 1;

	while(1)
	{
		int c=0;
		int mfd=-1;
		berrno be;
		fd_set fsr;
		fd_set fsw;
		fd_set fse;
		struct timeval tval;

		FD_ZERO(&fsr);
		FD_ZERO(&fse);

		tval.tv_sec=1;
		tval.tv_usec=0;

		add_fd_to_sets(rfd, &fsr, NULL, &fse, &mfd);
		if(sfd>=0) add_fd_to_sets(sfd, &fsr, NULL, &fse, &mfd);

		// Add read fds of normal children.
		for(c=0; c<conf->max_children; c++)
		  if(!chlds[c].status_server && chlds[c].rfd>=0)
			add_fd_to_sets(chlds[c].rfd, &fsr, NULL, &fse, &mfd);

		if(select(mfd+1, &fsr, NULL, &fse, &tval)<0)
		{
			if(errno!=EAGAIN && errno!=EINTR)
			{
				logp("select error: %s\n", strerror(errno));
				ret=1;
				break;
			}
		}

		if(FD_ISSET(rfd, &fse))
		{
			// Happens when a client exits.
			//logp("error on listening socket.\n");
			if(!forking) break;
			continue;
		}

		if((sfd>=0 && FD_ISSET(sfd, &fse)))
		{
			// Happens when a client exits.
			//logp("error on status socket.\n");
			if(!forking) break;
			continue;
		}

		if(FD_ISSET(rfd, &fsr))
		{
			// A normal client is incoming.
			if(process_incoming_client(rfd, forking, conf, ctx,
				configfile, 0 /* not a status client */))
			{
				ret=1;
				break;
			}
		}

		if(sfd>=0 && FD_ISSET(sfd, &fsr))
		{
			// A status client is incoming.
			//printf("status client?\n");
			if(process_incoming_client(sfd, forking, conf, ctx,
				configfile, 1 /* a status client */))
			{
				ret=1;
				break;
			}
		}

		for(c=0; c<conf->max_children; c++)
		{
		  if(!chlds[c].status_server && chlds[c].rfd>=0)
		  {
			if(FD_ISSET(chlds[c].rfd, &fse))
				continue;
			if(FD_ISSET(chlds[c].rfd, &fsr))
			{
				int l;
				// A child is giving us some status
				// information.
				static char buf[1024]="";
				if(chlds[c].data)
				{
					free(chlds[c].data);
					chlds[c].data=NULL;
				}
				if((l=read(chlds[c].rfd, buf, sizeof(buf)-2))>0)
				{
					// If we did not get a full read, do
					// not worry, just throw it away.
					if(buf[l-1]=='\n')
					{
						buf[l]='\0';
						chlds[c].data=strdup(buf);
						//logp("got status: %s",
						//	chlds[c].data);
						// Try to get a name for the
						// child.
						if(!chlds[c].name)
						{
							char *cp=NULL;
							if((cp=strchr(buf,'\t')))
							{
								*cp='\0';
								chlds[c].name=strdup(buf);
							}
						}
					}
				}
				if(l<=0) close_fd(&(chlds[c].rfd));
			}
		  }
		}


		// Have a separate select for writing to status server children

		mfd=-1;
		FD_ZERO(&fsw);
		FD_ZERO(&fse);
		for(c=0; c<conf->max_children; c++)
		  if(chlds[c].status_server && chlds[c].wfd>=0)
			add_fd_to_sets(chlds[c].wfd, NULL, &fsw, &fse, &mfd);
		if(mfd==-1)
		{
			// Did not find any status server children.
			// No need to do the select.
			continue;
		}

		// Do not hang around - doing the status stuff is a lower
		// priority thing than dealing with normal clients.
		tval.tv_sec=0;
		tval.tv_usec=500;

		//printf("try status server\n");

		if(select(mfd+1, NULL, &fsw, &fse, &tval)<0)
		{
			if(errno!=EAGAIN && errno!=EINTR)
			{
				logp("select error: %s\n", strerror(errno));
				ret=1;
				break;
			}
		}

		for(c=0; c<conf->max_children; c++)
		{
		  if(chlds[c].status_server && chlds[c].wfd>=0)
		  {
			if(FD_ISSET(chlds[c].wfd, &fse))
			{
				logp("exception on status server write pipe\n");
				continue;
			}
			if(FD_ISSET(chlds[c].wfd, &fsw))
			{
				int d=0;
				//printf("ready for write\n");
				// Go through all the normal children and
				// write their statuses to the status child.
				for(d=0; d<conf->max_children; d++)
				{
				  if(!chlds[d].status_server && chlds[d].data)
				  {
				//	printf("try write\n");
					write(chlds[c].wfd, chlds[d].data,
						strlen(chlds[d].data));
				  }
				}
			}
		  }
		}
	}

	ssl_destroy_ctx(ctx);

	close_fd(&rfd);
	close_fd(&sfd);
	if(chlds)
	{
		int q=0;
		for(q=0; chlds && chlds[q].pid!=-2; q++)
			chldstat_free(&(chlds[q]));
		free(chlds);
	}

	return ret;
}
