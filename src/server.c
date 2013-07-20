#include "burp.h"
#include "prog.h"
#include "msg.h"
#include "lock.h"
#include "handy.h"
#include "asyncio.h"
#include "zlibio.h"
#include "counter.h"
#include "dpth.h"
#include "sbuf.h"
#include "auth_server.h"
#include "backup_server.h"
#include "current_backups_server.h"
#include "delete_server.h"
#include "list_server.h"
#include "restore_server.h"
#include "ssl.h"
#include "berrno.h"
#include "status_server.h"
#include "forkchild.h"
#include "autoupgrade_server.h"
#include "incexc_recv.h"
#include "incexc_send.h"
#include "ca_server.h"

#include <netdb.h>
#include <librsync.h>

static int sfd=-1; // status fd for the main server

static int hupreload=0;
static int hupreload_logged=0;
static int gentleshutdown=0;
static int gentleshutdown_logged=0;
static int sigchld=0;

static void huphandler(int sig)
{
	hupreload=1;
	// Be careful about not logging inside a signal handler.
	hupreload_logged=0;
}

static void usr2handler(int sig)
{
	gentleshutdown=1;
	// Be careful about not logging inside a signal handler.
	gentleshutdown_logged=0;
}

static int init_listen_socket(const char *port, int alladdr)
{
	int rfd;
	int gai_ret;
#ifdef HAVE_IPV6
	int no = 0;
	int sockopt_ret = 0;
#endif
	struct addrinfo hints;
	struct addrinfo *result=NULL;
	struct addrinfo *rp=NULL;

	memset(&hints, 0, sizeof(struct addrinfo));
#ifdef HAVE_IPV6
	hints.ai_family = AF_INET6;
#else
	hints.ai_family = AF_INET;
#endif /* HAVE_IPV6 */
	hints.ai_socktype = SOCK_STREAM;
	hints.ai_flags = alladdr ? AI_PASSIVE : 0;
	hints.ai_protocol = IPPROTO_TCP;
	hints.ai_canonname = NULL;
	hints.ai_addr = NULL;
	hints.ai_next = NULL;

	if((gai_ret=getaddrinfo(NULL, port, &hints, &result)))
	{
		logp("unable to getaddrinfo on port %s: %s\n",
			port, gai_strerror(gai_ret));
		return -1;
	}

	for(rp=result; rp; rp=rp->ai_next)
	{
		rfd=socket(rp->ai_family, rp->ai_socktype, rp->ai_protocol);
		if(rfd<0)
		{
			logp("unable to create socket on port %s: %s\n",
				port, strerror(errno));
			continue;
		}
		if(!bind(rfd, rp->ai_addr, rp->ai_addrlen)) break;
		logp("unable to bind socket on port %s: %s\n",
			port, strerror(errno));
		close(rfd);
		rfd=-1;
	}
	if(!rp || rfd<0)
	{
		logp("unable to bind listening socket on port %s\n", port);
		return -1;
	}

#ifdef HAVE_IPV6
	if (rp->ai_family == AF_INET6) {
		sockopt_ret = setsockopt(rfd, IPPROTO_IPV6, IPV6_V6ONLY, &no, sizeof(no));
	}

	if(!sockopt_ret)
	{
		logp("unable to change socket option to "
			"listen on both IPv4 and IPv6\n");
		return -1;
	}
#endif

	freeaddrinfo(result);

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
// Update: This is no longer true, because dealing with chlds is now done
// outside of sigchld_handler.
// TODO: Make chlds not be a global.
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
		// Logging a message here appeared to occasionally lock burp
		// up on a Ubuntu server that I use.
		//logp("child pid %d exited\n", p);
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
	sigchld=1;
}

int setup_signals(int oldmax_children, int max_children, int oldmax_status_children, int max_status_children)
{
	// Ignore SIGPIPE - we are careful with read and write return values.
	int p=0;
	int total_max_children=max_children+max_status_children;
	int total_oldmax_children=oldmax_children+oldmax_status_children;
	signal(SIGPIPE, SIG_IGN);
	// Get rid of defunct children.
	if(!(chlds=(struct chldstat *)
		realloc(chlds, sizeof(struct chldstat)*(total_max_children+1))))
	{
		log_out_of_memory(__FUNCTION__);
		return -1;
	}
	if((p=total_oldmax_children-1)<0) p=0;
	for(; p<total_max_children+1; p++)
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
	chlds[total_max_children].pid=-2;

	setup_signal(SIGCHLD, sigchld_handler);
	//setup_signal(SIGABRT, sighandler);
	//setup_signal(SIGTERM, sighandler);
	//setup_signal(SIGINT, sighandler);
	setup_signal(SIGHUP, huphandler);
	setup_signal(SIGUSR2, usr2handler);

	return 0;
}

/*
static int incexc_matches(const char *fullrealwork, const char *incexc)
{
	int ret=0;
	int got=0;
	FILE *fp=NULL;
	char buf[4096]="";
	const char *inc=NULL;
	char *old_incexc_path=NULL;
	if(!(old_incexc_path=prepend_s(fullrealwork,
		"incexc", strlen("incexc"))))
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

static int get_lock_w(const char *lockbasedir, const char *lockfile, char **gotlock)
{
	int ret=0;
	char *copy=NULL;
	// Make sure the lock directory exists.
	if(!(copy=strdup(lockfile))
	  || mkpath(&copy, lockbasedir))
	{
		async_write_str(CMD_ERROR, "problem with lock directory");
		if(copy) free(copy);
		return -1;
	}
	free(copy);

	if(get_lock(lockfile))
	{
		logp("another instance of client is already running,\n");
		logp("or %s is not writable.\n", lockfile);
		async_write_str(CMD_ERROR, "another instance is already running");
		ret=-1;
	}
	else
	{
		if(*gotlock) free(*gotlock);
		if(!(*gotlock=strdup(lockfile)))
		{
			log_out_of_memory(__FUNCTION__);
			ret=-1;
		}
	}

	return ret;
}

/* I am sure I wrote this function already, somewhere else. */
static int reset_conf_val(const char *src, char **dest)
{
	if(src)
	{
		if(*dest) free(*dest);
		if(!(*dest=strdup(src)))
		{
			log_out_of_memory(__FUNCTION__);
			return -1;
		}
	}
	return 0;
}

static char *get_restorepath(struct config *cconf, const char *client)
{
	char *tmp=NULL;
	char *restorepath=NULL;
	if(!(tmp=prepend_s(cconf->directory, client, strlen(client)))
	 || !(restorepath=prepend_s(tmp, "restore", strlen("restore"))))
	{
		if(tmp) free(tmp);
		return NULL;
	}
	free(tmp);
	return restorepath;
}

static int client_can_restore(struct config *cconf, const char *client)
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

static void maybe_do_notification(int status, const char *client, const char *basedir, const char *storagedir, const char *filename, const char *brv, struct config *cconf, struct cntr *p1cntr, struct cntr *cntr)
{
	int a=0;
	const char *args[12];
	args[a++]=NULL; // Fill in the script name later.
	args[a++]=client;
	args[a++]=basedir;
	args[a++]=storagedir;
	args[a++]=filename;
	args[a++]=brv;
	if(status)
	{
		args[0]=cconf->notify_failure_script;
		args[a++]="0";
		args[a++]=NULL;
		run_script(args, cconf->notify_failure_arg, cconf->nfcount,
			cntr, 1, 1);
	}
	else if((cconf->notify_success_warnings_only
		&& (p1cntr->warning+cntr->warning)>0)
	  || (cconf->notify_success_changes_only
		&& (cntr->total_changed>0))
	  || (!cconf->notify_success_warnings_only
		&& !cconf->notify_success_changes_only))
	{
		char warnings[32]="";
		snprintf(warnings, sizeof(warnings), "%llu",
			p1cntr->warning+cntr->warning);
		args[0]=cconf->notify_success_script;
		args[a++]=warnings;
		args[a++]=NULL;
		run_script(args, cconf->notify_success_arg, cconf->nscount,
			cntr, 1, 1);
	}
}

static int child(struct config *conf, struct config *cconf, const char *client, const char *cversion, const char *incexc, int srestore, char cmd, char *buf, char **gotlock, int *timer_ret, struct cntr *p1cntr, struct cntr *cntr)
{
	int ret=0;
	char msg[256]="";
	char *basedir=NULL;
	// Do not allow a single client to connect more than once
	char *lockbasedir=NULL;
	char *lockfile=NULL;
	// The previous backup
	char *current=NULL;
	// The one we are working on
	char *working=NULL;
	// The full path to the latest backup data
	char *currentdata=NULL;
	// where the data goes initially
	char *datadirtmp=NULL;
	// The final compressed manifest 
	char *manifest=NULL;
	// A symlink that indicates that the
	// data from the client is complete and just some work on the server 
	// is needed to finish. The 'working' symlink gets renamed to this
	// at the appropriate moment.
	char *finishing=NULL;
	char *client_lockdir=NULL;

	if(!(client_lockdir=conf->client_lockdir))
		client_lockdir=cconf->directory;

	if(!(basedir=prepend_s(cconf->directory, client, strlen(client)))
	  || !(working=prepend_s(basedir, "working", strlen("working")))
	  || !(finishing=prepend_s(basedir, "finishing", strlen("finishing")))
	  || !(current=prepend_s(basedir, "current", strlen("current")))
	  || !(currentdata=prepend_s(current, "data", strlen("data")))
	  || !(manifest=prepend_s(working, "manifest.gz", strlen("manifest.gz")))
	  || !(datadirtmp=prepend_s(working, "data.tmp", strlen("data.tmp")))
	  || !(lockbasedir=prepend_s(client_lockdir, client, strlen(client)))
	  || !(lockfile=prepend_s(lockbasedir, "lockfile", strlen("lockfile"))))
	{
		log_and_send_oom(__FUNCTION__);
		ret=-1;
	}
	else if(cmd==CMD_GEN
	  && !strncmp(buf, "backup", strlen("backup")))
	{
		if(cconf->restore_client)
		{
			// This client is not the original client, so a
			// backup might cause all sorts of trouble.
			logp("Not allowing backup of %s\n", client);
			async_write_str(CMD_GEN, "Backup is not allowed");
			goto end;
		}

		// Set quality of service bits on backups.
		set_bulk_packets();
		if(get_lock_w(lockbasedir, lockfile, gotlock))
			ret=-1;
		else
		{
			char okstr[32]="";
			// create basedir, without the /current part
			if(mkpath(&current, cconf->directory))
			{
				snprintf(msg, sizeof(msg),
					"could not mkpath %s", current);
				log_and_send(msg);
				ret=-1;
				goto end;
			}
			if(!strcmp(buf, "backup_timed"))
			{
				int a=0;
				const char *args[12];
				args[a++]=cconf->timer_script;
				args[a++]=client;
				args[a++]=current;
				args[a++]=cconf->directory;
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
					ret=*timer_ret;
					logp("Error running timer script for %s\n", client);
					goto end;
				}
				if(*timer_ret)
				{
					logp("Not running backup of %s\n",
						client);
					async_write_str(CMD_GEN,
						"timer conditions not met");
					goto end;
				}
				logp("Running backup of %s\n", client);
			}
			else
			{
				if(!cconf->client_can_force_backup)
				{
					logp("Not allowing forced backup of %s\n", client);
					async_write_str(CMD_GEN, "Forced backup is not allowed");
					goto end;
				}
			}

			buf=NULL;

			snprintf(okstr, sizeof(okstr), "ok:%d",
				cconf->compression);
			async_write_str(CMD_GEN, okstr);
			ret=do_backup_server(basedir, current, working,
			  currentdata, finishing, cconf,
			  manifest, client, cversion, p1cntr, cntr, incexc);
			maybe_do_notification(ret, client,
				basedir, current, "log", "backup",
				cconf, p1cntr, cntr);
		}
	}
	else if(cmd==CMD_GEN
	  && (!strncmp(buf, "restore ", strlen("restore "))
		|| !strncmp(buf, "verify ", strlen("verify "))))
	{
		char *cp=NULL;
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
		reset_conf_val(backupnostr, &(cconf->backup));
		if((cp=strchr(cconf->backup, ':'))) *cp='\0';

		if(get_lock_w(lockbasedir, lockfile, gotlock))
			ret=-1;
		else
		{
			char *restoreregex=NULL;
			char *dir_for_notify=NULL;

			if(act==ACTION_RESTORE)
			{
				int r;
				if((r=client_can_restore(cconf, client))<0)
				{
					ret=-1;
					goto end;
				}
				else if(!r)
				{
					logp("Not allowing restore of %s\n",
						client);
					async_write_str(CMD_GEN,
					  "Client restore is not allowed");
					goto end;
				}
			}
			if(act==ACTION_VERIFY && !cconf->client_can_verify)
			{
				logp("Not allowing verify of %s\n", client);
				async_write_str(CMD_GEN,
					"Client verify is not allowed");
				goto end;
			}

			if((restoreregex=strchr(buf, ':')))
			{
				*restoreregex='\0';
				restoreregex++;
			}
			reset_conf_val(restoreregex, &(cconf->regex));
			async_write_str(CMD_GEN, "ok");
			ret=do_restore_server(basedir, act, client, srestore,
				&dir_for_notify, p1cntr, cntr, cconf);
			if(dir_for_notify)
			{
				maybe_do_notification(ret, client,
					basedir, dir_for_notify,
					act==ACTION_RESTORE?
						"restorelog":"verifylog",
					act==ACTION_RESTORE?
						"restore":"verify",
					cconf, p1cntr, cntr);
				free(dir_for_notify);
			}
		}
	}
	else if(cmd==CMD_GEN && !strncmp(buf, "delete ", strlen("delete ")))
	{
		if(get_lock_w(lockbasedir, lockfile, gotlock))
			ret=-1;
		else
		{
			char *backupno=NULL;
			if(!cconf->client_can_delete)
			{
				logp("Not allowing delete of %s\n", client);
				async_write_str(CMD_GEN,
					"Client delete is not allowed");
				goto end;
			}
			backupno=buf+strlen("delete ");
			ret=do_delete_server(basedir, backupno, client, p1cntr, cntr);
		}
	}
	else if(cmd==CMD_GEN
	  && (!strncmp(buf, "list ", strlen("list "))
	      || !strncmp(buf, "listb ", strlen("listb "))))
	{
		if(get_lock_w(lockbasedir, lockfile, gotlock))
			ret=-1;
		else
		{
			char *backupno=NULL;
			char *browsedir=NULL;
			char *listregex=NULL;

			if(!cconf->client_can_list)
			{
				logp("Not allowing list of %s\n", client);
				async_write_str(CMD_GEN,
					"Client list is not allowed");
				goto end;
			}

			if(!strncmp(buf, "list ", strlen("list ")))
			{
				if((listregex=strrchr(buf, ':')))
				{
					*listregex='\0';
					listregex++;
				}
				backupno=buf+strlen("list ");
			}
			else if(!strncmp(buf, "listb ", strlen("listb ")))
			{
				if((browsedir=strchr(buf, ':')))
				{
					*browsedir='\0';
					browsedir++;
				}
				// strip any trailing slashes
				// (unless it is '/').
				if(strcmp(browsedir, "/")
				 && browsedir[strlen(browsedir)-1]=='/')
				  browsedir[strlen(browsedir)-1]='\0';
				backupno=buf+strlen("listb ");
			}
			async_write_str(CMD_GEN, "ok");
			ret=do_list_server(basedir, backupno,
				listregex, browsedir, client, p1cntr, cntr);
		}
	}
	else
	{
		logp("unknown command: %c:%s\n", cmd, buf);
		async_write_str(CMD_ERROR, "unknown command");
		ret=-1;
	}

end:
	if(basedir) free(basedir);
	if(current) free(current);
	if(finishing) free(finishing);
	if(working) free(working);
	if(currentdata) free(currentdata);
	if(datadirtmp) free(datadirtmp);
	if(manifest) free(manifest);
	if(lockbasedir) free(lockbasedir);
	if(lockfile) free(lockfile);
	return ret;
}

static int append_to_feat(char **feat, const char *str)
{
	char *tmp=NULL;
	if(!*feat)
	{
		if(!(*feat=strdup(str)))
		{
			log_out_of_memory(__FUNCTION__);
			return -1;
		}
		return 0;
	}
	if(!(tmp=prepend(*feat, str, strlen(str), "")))
		return -1;
	free(*feat);
	*feat=tmp;
	return 0;
}

static int extra_comms(char **client, const char *cversion, char **incexc, int *srestore, struct config *conf, struct config *cconf, struct cntr *p1cntr)
{
	int ret=0;
	char *buf=NULL;
	long min_ver=0;
	long cli_ver=0;
	long ser_ver=0;
	long feat_list_ver=0;
	long directory_tree_ver=0;
	//char *restorepath=NULL;

	if((min_ver=version_to_long("1.2.7"))<0
	 || (cli_ver=version_to_long(cversion))<0
	 || (ser_ver=version_to_long(VERSION))<0
	 || (feat_list_ver=version_to_long("1.3.0"))<0
	 || (directory_tree_ver=version_to_long("1.3.6"))<0)
		return -1;

	if(cli_ver < directory_tree_ver)
	{
		conf->directory_tree=0;
		cconf->directory_tree=0;
	}

	// Clients before 1.2.7 did not know how to do extra comms, so skip
	// this section for them.
	if(cli_ver < min_ver) return 0;

	if(async_read_expect(CMD_GEN, "extra_comms_begin"))
	{
		logp("problem reading in extra_comms\n");
		return -1;
	}
	// Want to tell the clients the extra comms features that are
	// supported, so that new clients are more likely to work with old
	// servers.
	if(cli_ver==feat_list_ver)
	{
		// 1.3.0 did not support the feature list.
		if(async_write_str(CMD_GEN, "extra_comms_begin ok"))
		{
			logp("problem writing in extra_comms\n");
			return -1;
		}
	}
	else
	{
		//char *tmp=NULL;
		char *feat=NULL;
		struct stat statp;
		if(append_to_feat(&feat, "extra_comms_begin ok:")
			/* clients can autoupgrade */
		  || append_to_feat(&feat, "autoupgrade:")
			/* clients can give server incexc config so that the
			   server knows better what to do on resume */
		  || append_to_feat(&feat, "incexc:")
			/* clients can give the server an alternative client
			   to restore from */
		  || append_to_feat(&feat, "orig_client:"))
			return -1;

		/* Clients can receive restore initiated from the server. */
		if(cconf->restore_path) free(cconf->restore_path);
		if(!(cconf->restore_path=get_restorepath(cconf, *client)))
		{
			if(feat) free(feat);
			return -1;
		}
		if(!lstat(cconf->restore_path, &statp) && S_ISREG(statp.st_mode)
		  && append_to_feat(&feat, "srestore:"))
		{
			if(feat) free(feat);
			return -1;
		}

		/* Clients can receive incexc config from the server.
		   Only give it as an option if the server has some starting
		   directory configured in the clientconfdir. */
		if(cconf->sdcount && append_to_feat(&feat, "sincexc:"))
			return -1;

		/* Clients can be sent counters on resume/verify/restore. */
		if(append_to_feat(&feat, "counters:"))
			return -1;

		//printf("feat: %s\n", feat);

		if(async_write_str(CMD_GEN, feat))
		{
			logp("problem in extra_comms\n");
			free(feat);
			return -1;
		}
		free(feat);
	}

	while(1)
	{
		char cmd;
		size_t len=0;

		if(async_read(&cmd, &buf, &len))
		{
			ret=-1;
			break;
		}

		if(cmd==CMD_GEN)
		{
			if(!strcmp(buf, "extra_comms_end"))
			{
				if(async_write_str(CMD_GEN,
					"extra_comms_end ok"))
						ret=-1;
				break;
			}
			else if(!strncmp(buf,
				"autoupgrade:", strlen("autoupgrade:")))
			{
				char *os=NULL;
				os=buf+strlen("autoupgrade:");
				if(os && *os
				  && autoupgrade_server(ser_ver, cli_ver, os,
					conf, p1cntr))
				{
					ret=-1;
					break;
				}
			}
			else if(!strcmp(buf, "srestore ok"))
			{
				// Client can accept the restore.
				// Load the restore config, then send it.
				*srestore=1;
				if(parse_incexcs_path(cconf,cconf->restore_path)
				  || incexc_send_server_restore(cconf, p1cntr))
				{
					ret=-1;
					break;
				}
				// Do not unlink it here - wait until
				// the client says that it wants to do the
				// restore.
				// Also need to leave it around if the
				// restore is to an alternative client, so
				// that the code below that reloads the config
				// can read it again.
				//unlink(cconf->restore_path);
			}
			else if(!strcmp(buf, "srestore not ok"))
			{
				// Client will not accept the restore.
				unlink(cconf->restore_path);
				free(cconf->restore_path);
				cconf->restore_path=NULL;
				logp("Client not accepting server initiated restore.\n");
			}
			else if(!strcmp(buf, "sincexc ok"))
			{
				// Client can accept incexc conf from the
				// server.
				if(incexc_send_server(cconf, p1cntr))
				{
					ret=-1;
					break;
				}
			}
			else if(!strcmp(buf, "incexc"))
			{
				// Client is telling server its incexc
				// configuration so that it can better decide
				// what to do on resume.
				if(*incexc) { free(*incexc); *incexc=NULL; }
				if(incexc_recv_server(incexc, conf, p1cntr))
				{
					ret=-1;
					break;
				}
				if(*incexc)
				{
					char *tmp=NULL;
					char comp[32]="";
					snprintf(comp, sizeof(comp),
						"compression = %d\n",
						cconf->compression);
					if(!(tmp=prepend(*incexc, comp,
						strlen(comp), 0)))
					{
						ret=-1;
						break;
					}
					free(*incexc);
					*incexc=tmp;
				}
			}
			else if(!strcmp(buf, "countersok"))
			{
				// Client can accept counters on
				// resume/verify/restore.
				logp("Client supports being sent counters.\n");
				cconf->send_client_counters=1;
			}
			else if(!strncmp(buf,
				"orig_client=", strlen("orig_client="))
			  && strlen(buf)>strlen("orig_client="))
			{
				int r=0;
				int rcok=0;
				struct config *sconf=NULL;
				const char *orig_client=NULL;
				orig_client=buf+strlen("orig_client=");

				if(!(sconf=(struct config *)
					malloc(sizeof(struct config))))
				{
					log_out_of_memory(__FUNCTION__);
					ret=-1;
					break;
				}
				logp("Client wants to switch to client: %s\n",
					orig_client);
				if(load_client_config(conf, sconf,
					orig_client))
				{
					char msg[256]="";
					snprintf(msg, sizeof(msg), "Could not load alternate config: %s", orig_client);
					log_and_send(msg);
					ret=-1;
					break;
				}
				sconf->send_client_counters=
					cconf->send_client_counters;
				for(r=0; r<sconf->rccount; r++)
				{
					if(sconf->rclients[r])
					{
					  if(!strcmp(sconf->rclients[r]->path,
						*client))
					  {
						rcok++;
						break;
					  }
					}
				}

				if(!rcok)
				{
					char msg[256]="";
					snprintf(msg, sizeof(msg),
					  "Access to client is not allowed: %s",
						orig_client);
					log_and_send(msg);
					ret=-1;
					break;
				}
				sconf->restore_path=cconf->restore_path;
				cconf->restore_path=NULL;
				free_config(cconf);
				memcpy(cconf, sconf, sizeof(struct config));
				sconf=NULL;
				cconf->restore_client=*client;
				if(!(*client=strdup(orig_client))
				  || !(cconf->orig_client=strdup(orig_client)))
				{
					log_and_send_oom(__FUNCTION__);
					ret=-1;
					break;
				}
				orig_client=NULL;

				// If this started out as a server-initiated
				// restore, need to load the restore file
				// again.
				if(*srestore)
				{
					if(parse_incexcs_path(cconf,
						cconf->restore_path))
					{
						ret=-1;
						break;
					}
				}
				logp("Switched to client %s\n", *client);
				if(async_write_str(CMD_GEN, "orig_client ok"))
				{
					ret=-1;
					break;
				}
			}
			else
			{
				logp("unexpected command from client: %c:%s\n",
					cmd, buf);
				ret=-1;
				break;
			}
		}
		else
		{
			logp("unexpected command from client: %c:%s\n",
				cmd, buf);
			ret=-1;
			break;
		}

		if(buf); free(buf); buf=NULL;
	}

	if(buf) free(buf);
	return ret;
}

static int run_child(int *rfd, int *cfd, SSL_CTX *ctx, const char *configfile, int forking)
{
	int ret=0;
	char cmd;
	int ca_ret=0;
	size_t len=0;
	char *buf=NULL;
	SSL *ssl=NULL;
	BIO *sbio=NULL;
	char *incexc=NULL;
	char *client=NULL;
	char *cversion=NULL;
	int srestore=0;
	char *gotlock=NULL;
	int timer_ret=0;
	struct config conf;
	struct config cconf;

	struct cntr p1cntr; // cntr for scan
	struct cntr cntr; // cntr for the rest

	reset_filecounter(&p1cntr, time(NULL));
	reset_filecounter(&cntr, time(NULL));

	if(forking) close_fd(rfd);

	// Reload global config, in case things have changed. This means that
	// the server does not need to be restarted for most config changes.
	init_config(&conf);
	init_config(&cconf);
	if(load_config(configfile, &conf, 1)) return -1;

	if(!(sbio=BIO_new_socket(*cfd, BIO_NOCLOSE))
	  || !(ssl=SSL_new(ctx)))
	{
		logp("There was a problem joining ssl to the socket\n");
		ret=-1;
		goto finish;
	}
	SSL_set_bio(ssl, sbio, sbio);

	/* Do not try to check peer certificate straight away.
	   Clients can send a certificate signing request when they have
	   no certificate.
	*/
	SSL_set_verify(ssl, SSL_VERIFY_PEER
		/* | SSL_VERIFY_FAIL_IF_NO_PEER_CERT */, 0);

	if((ret=SSL_accept(ssl))<=0)
	{
		char buf[256]="";
		ERR_error_string_n(ERR_get_error(), buf, sizeof(buf));
		logp("SSL_accept: %s\n", buf);
		ret=-1;
		goto finish;
	}
	ret=0;
	if(async_init(*cfd, ssl, &conf, 0))
	{
		ret=-1;
		goto finish;
	}
	if(authorise_server(&conf, &client, &cversion, &cconf, &p1cntr)
		|| !client || !*client)
	{
		// add an annoying delay in case they are tempted to
		// try repeatedly
		log_and_send("unable to authorise on server");
		sleep(1);
		ret=-1;
		goto finish;
	}

	/* At this point, the client might want to get a new certificate
	   signed. Clients on 1.3.2 or newer can do this. */
	if((ca_ret=ca_server_maybe_sign_client_cert(client, cversion,
		&conf, &p1cntr))<0)
	{
		// Error.
		logp("Error signing client certificate request for %s\n",
			client);
		ret=-1;
		goto finish;
	}
	else if(ca_ret>0)
	{
		// Certificate signed and sent back.
		// Everything is OK, but we will close this instance
		// so that the client can start again with a new
		// connection and its new certificates.
		logp("Signed and returned client certificate request for %s\n",
			client);
		goto finish;
	}

	/* Now it is time to check the certificate. */ 
	if(ssl_check_cert(ssl, &cconf))
	{
		log_and_send("check cert failed on server");
		return -1;
	}

	/* Has to be before the chuser/chgrp stuff to allow clients to switch
	   to different clients when both clients have different user/group
	   settings. */
	if(extra_comms(&client, cversion, &incexc, &srestore,
		&conf, &cconf, &p1cntr))
	{
		log_and_send("running extra comms failed on server");
		ret=-1;
		goto finish;
	}

	// Now that the client conf is loaded, we might want to chuser or
	// chgrp.
	// The main process could have already done this, so we don't want
	// to try doing it again if cconf has the same values, because it
	// will fail.
	if(  (!conf.user  || (cconf.user && strcmp(conf.user, cconf.user)))
	  || (!conf.group || (cconf.group && strcmp(conf.group, cconf.group))))
	{
		if(chuser_and_or_chgrp(cconf.user, cconf.group))
		{
			log_and_send("chuser_and_or_chgrp failed on server");
			ret=-1;
			goto finish;
		}
	}

	set_non_blocking(*cfd);

	if(async_read(&cmd, &buf, &len))
	{
		ret=-1;
	}

	if(cconf.server_script_pre)
	{
		int a=0;
		char *logbuf=NULL;
		const char *args[12];
		args[a++]=cconf.server_script_pre;
		args[a++]="pre";
		args[a++]=buf?buf:"";
		args[a++]=client;
		args[a++]="reserved4";
		args[a++]="reserved5";
		args[a++]=NULL;
		// At this point, there is no client directory and therefore
		// log file on the server.
		// So to log the output, we have to catch it in a buffer,
		// then pass the buffer to the notification script.
		if(run_script_to_buf(args, cconf.server_script_pre_arg,
			cconf.sprecount, NULL, 1, 1, &logbuf))
		{
			log_and_send("server pre script returned an error");
			ret=-1;
			if(cconf.server_script_pre_notify)
			{
				a=0;
				args[a++]=cconf.notify_failure_script;
				args[a++]=client;
				// magic - set basedir blank and the
				// notify script will know to get the content
				// from the next argument (usually storagedir)
				args[a++]=""; // usually basedir
				args[a++]=logbuf?logbuf:""; //usually storagedir
				args[a++]=""; // usually file
				args[a++]=""; // usually brv
				args[a++]=""; // usually warnings
				args[a++]=NULL;
				run_script(args,
					cconf.notify_failure_arg,
					cconf.nfcount,
					NULL, 1, 1);
			}
			// Do not finish here, because the server post script
			// might want to run.
		}
		if(logbuf) free(logbuf);
	}

	if(!ret) ret=child(&conf, &cconf, client, cversion, incexc, srestore,
			cmd, buf, &gotlock, &timer_ret, &p1cntr, &cntr);

	if((!ret || cconf.server_script_post_run_on_fail)
	  && cconf.server_script_post)
	{
		int a=0;
		char *logbuf=NULL;
		const char *args[12];
		args[a++]=cconf.server_script_post;
		args[a++]="post";
		args[a++]=buf?buf:"", // the action requested by the client
		args[a++]=client;
		args[a++]=ret?"1":"0", // indicate success or failure
		// indicate whether the timer script said OK or not
		args[a++]=timer_ret?"1":"0",
		args[a++]=NULL;
		// Do not have a client storage directory, so capture the
		// output in a buffer to pass to the notification script.
		if(run_script_to_buf(args,
			cconf.server_script_post_arg, cconf.spostcount,
			NULL, 1, 1, &logbuf))
		{
			log_and_send("server post script returned an error");
			ret=-1;
			if(cconf.server_script_post_notify)
			{
				a=0;
				args[a++]=cconf.notify_failure_script;
				args[a++]=client;
				// magic - set basedir blank and the
				// notify script will know to get the content
				// from the next argument (usually storagedir)
				args[a++]=""; // usually basedir
				args[a++]=logbuf?logbuf:""; //usually storagedir
				args[a++]=""; // usually file
				args[a++]=""; // usually brv
				args[a++]=""; // usually warnings
				args[a++]=NULL;
				run_script(args,
					cconf.notify_failure_arg,
					cconf.nfcount,
					NULL, 1, 1);
			}
			if(logbuf) free(logbuf);
			goto finish;
		}
		if(logbuf) free(logbuf);
	}

finish:
	*cfd=-1;
	if(gotlock)
	{
		unlink(gotlock);
		free(gotlock);
	}
	async_free(); // this closes cfd for us.
	logp("exit child\n");
	if(client) free(client);
	if(cversion) free(cversion);
	if(buf) free(buf);
	if(incexc) free(incexc);
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
	if(load_config(configfile, &conf, TRUE)) return -1;

	ret=status_server(cfd, &conf);

	close_fd(cfd);

	logp("exit status server\n");

	free_config(&conf);

	return ret;
}

static int process_incoming_client(int rfd, struct config *conf, SSL_CTX *ctx, const char *configfile, int is_status_server)
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

	if(conf->forking)
	{
	  int p=0;
	  int pipe_rfd[2];
	  int pipe_wfd[2];
	  pid_t childpid;
	  int c_count=0;
	  int sc_count=0;
	  int total_max_children=conf->max_children+conf->max_status_children;

	  /* Need to count status children separately from normal children. */
	  for(p=0; p<total_max_children; p++)
	  {
		if(chlds[p].pid>=0)
		{
			if(chlds[p].status_server) sc_count++;
			else c_count++;
		}
	  }

	  if(!is_status_server && c_count>=conf->max_children)
	  {
		logp("Too many child processes. Closing new connection.\n");
		close_fd(&cfd);
		return 0;
	  }
	  if(is_status_server && sc_count>=conf->max_status_children)
	  {
		logp("Too many status child processes. Closing new connection.\n");
		close_fd(&cfd);
		return 0;
	  }

	  // Find a spare slot in our pid list for the child.
	  for(p=0; p<total_max_children; p++)
	  {
		if(chlds[p].pid<0) break;
	  }
	  if(p>=total_max_children)
	  {
		logp("Too many total child processes. Closing new connection.\n");
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
			  ret=run_child(&rfd, &cfd, ctx,
				configfile, conf->forking);
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
			return run_child(&rfd, &cfd, ctx, configfile,
				conf->forking);
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

static int run_server(struct config *conf, const char *configfile, int *rfd, const char *oldport, const char *oldstatusport)
{
	int ret=0;
	SSL_CTX *ctx=NULL;
	int found_normal_child=0;

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

	if(!oldport
	  || strcmp(oldport, conf->port))
	{
		close_fd(rfd);
		if((*rfd=init_listen_socket(conf->port, 1))<0)
			return 1;
	}
	if(conf->status_port
	  && (!oldstatusport
		|| strcmp(oldstatusport, conf->status_port)))
	{
		close_fd(&sfd);
		if((sfd=init_listen_socket(conf->status_port, 0))<0)
			return 1;
	}

	while(!hupreload)
	{
		int c=0;
		int mfd=-1;
		berrno be;
		fd_set fsr;
		fd_set fsw;
		fd_set fse;
		struct timeval tval;

		if(sigchld)
		{
			check_for_exiting_children();
			sigchld=0;
		}

		FD_ZERO(&fsr);
		FD_ZERO(&fse);

		tval.tv_sec=1;
		tval.tv_usec=0;

		add_fd_to_sets(*rfd, &fsr, NULL, &fse, &mfd);
		if(sfd>=0) add_fd_to_sets(sfd, &fsr, NULL, &fse, &mfd);

		// Add read fds of normal children.
		if(gentleshutdown) found_normal_child=0;
		for(c=0; c<conf->max_children; c++)
		{
		  if(!chlds[c].status_server && chlds[c].rfd>=0)
		  {
			add_fd_to_sets(chlds[c].rfd, &fsr, NULL, &fse, &mfd);
			if(gentleshutdown) found_normal_child++;
		  }
		}
		// Leave if we had a SIGUSR1 and there are no children
		// running.
		if(gentleshutdown)
		{
			if(!gentleshutdown_logged)
			{
				logp("got SIGUSR2 gentle reload signal\n");
				logp("will shut down once children have exited\n");
				gentleshutdown_logged++;
			}
			else if(!found_normal_child)
			{
				logp("all children have exited - shutting down\n");
				break;
			}
		}

		if(select(mfd+1, &fsr, NULL, &fse, &tval)<0)
		{
			if(errno!=EAGAIN && errno!=EINTR)
			{
				logp("select error in normal part of %s: %s\n",
					__func__, strerror(errno));
				ret=1;
				break;
			}
		}

		if(FD_ISSET(*rfd, &fse))
		{
			// Happens when a client exits.
			//logp("error on listening socket.\n");
			if(!conf->forking) break;
			continue;
		}

		if((sfd>=0 && FD_ISSET(sfd, &fse)))
		{
			// Happens when a client exits.
			//logp("error on status socket.\n");
			if(!conf->forking) break;
			continue;
		}

		if(FD_ISSET(*rfd, &fsr))
		{
			// A normal client is incoming.
			if(process_incoming_client(*rfd, conf, ctx,
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
			if(process_incoming_client(sfd, conf, ctx,
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
				logp("select error in status part of %s: %s\n",
					__func__, strerror(errno));
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

	if(hupreload) logp("got SIGHUP reload signal\n");

	ssl_destroy_ctx(ctx);

	return ret;
}

int server(struct config *conf, const char *configfile, int generate_ca_only)
{
	int ret=0;
	int rfd=-1; // normal client port
	// Only close and reopen listening sockets if the ports changed.
	// Otherwise you get an "unable to bind listening socket on port X"
	// error, and the server stops.
	char *oldport=NULL;
	char *oldstatusport=NULL;

	if(ca_server_setup(conf)) return 1;
	if(generate_ca_only)
	{
		logp("The '-g' command line option was given. Exiting now.\n");
		return 0;
	}

	if(conf->forking && conf->daemon)
	{
		if(daemonise() || relock(conf->lockfile)) return 1;
	}

	ssl_load_globals();

	while(!ret && !gentleshutdown)
	{
		ret=run_server(conf, configfile,
			&rfd, oldport, oldstatusport);
		if(ret) break;
		if(hupreload && !gentleshutdown)
		{
			if(oldport) free(oldport);
			if(oldstatusport) free(oldstatusport);
			oldport=strdup(conf->port);
			oldstatusport=conf->status_port?
				strdup(conf->status_port):NULL;
			if(reload(conf, configfile,
				0 /* not first time */,
				conf->max_children,
				conf->max_status_children))
					ret=1;
		}
		hupreload=0;
	}
	close_fd(&rfd);
	close_fd(&sfd);
	if(oldport) free(oldport);
	if(oldstatusport) free(oldstatusport);
	
	if(chlds)
	{
		int q=0;
		for(q=0; chlds && chlds[q].pid!=-2; q++)
			chldstat_free(&(chlds[q]));
		free(chlds);
	}

	return ret;
}
