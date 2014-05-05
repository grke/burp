#include "include.h"
#include "burp2/client/main.h"
#include "burp2/server/status_client.h"
#include "burp2/server/main.h"
#include "burp2/server/champ_chooser/champ_server.h"

static char *get_conf_path(void)
{
	static char path[256]="";
#ifdef HAVE_WIN32
	char *pfenv=NULL;

	// Burp used to always install to 'C:/Program Files/Burp/', but as
	// of 1.3.11, it changed to %PROGRAMFILES%. Still want the old way
	// to work though. So check %PROGRAMFILES% first, then fall back.
	if((pfenv=getenv("PROGRAMFILES")))
	{
		struct stat statp;
		snprintf(path, sizeof(path), "%s/Burp/burp.conf", pfenv);
		if(!lstat(path, &statp)
		  && !S_ISDIR(statp.st_mode))
			return path;
	}
	snprintf(path, sizeof(path), "C:/Program Files/Burp/burp.conf");
#else
	snprintf(path, sizeof(path), "%s", SYSCONFDIR "/burp.conf");
#endif
	return path;
}

static void usage_server(void)
{
#ifndef HAVE_WIN32
	printf("\nThe configuration file specifies whether burp runs in server or client mode.\n");
	printf("\nServer usage: %s [options]\n", progname());
	printf("\n");
	printf(" Options:\n");
	printf("  -a c          Run as a stand-alone champion chooser.\n");
	printf("  -a s          Run the status monitor.\n");
	printf("  -a S          Screen dump of the status monitor (for reporting).\n");
	printf("  -c <path>     Path to conf file (default: %s).\n", get_conf_path());
	printf("  -d <path>     a single client in the status monitor.\n");
	printf("  -F            Stay in the foreground.\n");
	printf("  -g            Generate initial CA certificates and exit.\n");
	printf("  -h|-?         Print this text and exit.\n");
	printf("  -i            Print index of symbols and exit.\n");
	printf("  -l <path>     Path to log file.\n");
	printf("  -n            Do not fork any children (implies '-F').\n");
	printf("  -v            Print version and exit.\n");
	printf("Options to use with '-a c':\n");
	printf("  -C <client>   Run as if forked via a connection from this client.\n");
	printf("Options to use with '-a S':\n");
	printf("  -C <client>   Show a particular client.\n");
	printf("  -b <number>   Show listable files in a particular backup (requires -C).\n");
	printf("  -z <file>     Dump a particular log file in a backup (requires -C and -b).\n");
	printf("  -d <path>     Show a particular path in a backup (requires -C and -b).\n");
	printf("\n");
#endif
}

static void usage_client(void)
{
	printf("\nClient usage: %s [options]\n", progname());
	printf("\n");
	printf(" Options:\n");
	printf("  -a <action>    The action can be one of the following.\n");
	printf("                  b: backup\n");
	printf("                  e: estimate\n");
	printf("                  l: list (this is the default when an action is not given)\n");
	printf("                  L: long list\n");
	printf("                  r: restore\n");
	printf("                  t: timed backup\n");
	printf("                  T: check backup timer, but do not actually backup\n");
	printf("                  v: verify\n");
	printf("  -b <number>    Backup number (default: the most recent backup).\n");
	printf("  -c <path>      Path to conf file (default: %s).\n", get_conf_path());
	printf("  -d <directory> Directory to restore to, or directory to list.\n");
	printf("  -f             Allow overwrite during restore.\n");
	printf("  -h|-?          Print this text and exit.\n");
	printf("  -i             Print index of symbols and exit.\n");
	printf("  -l <path>      Path to log file.\n");
	printf("  -r <regex>     Specify a regular expression.\n");
	printf("  -s <number>    Number of leading path components to strip during restore.\n");
	printf("  -j             Format long list as JSON.\n");
	printf("  -v             Print version and exit.\n");
#ifndef HAVE_WIN32
	printf("  -x             Do not use the Windows VSS API when restoring.\n");
#endif
	printf("\n");
#ifndef HAVE_WIN32
	printf(" See http://burp.grke.net/ or the man page ('man burp') for usage examples\n");
	printf(" and additional configuration options.\n\n");
#else
	printf(" See http://burp.grke.net/ for usage examples and additional configuration\n");
	printf(" options.\n\n");
#endif
}

int reload(struct conf *conf, const char *conffile, bool firsttime,
	int oldmax_children, int oldmax_status_children, int json)
{
	if(!firsttime) logp("Reloading config\n");

	conf_init(conf);

	if(conf_load(conffile, conf, 1)) return 1;

	/* change umask */
	umask(conf->umask);

        // Try to make JSON output clean.
        if(json) conf->log_to_stdout=0;

	// This will turn on syslogging which could not be turned on before
	// conf_load.
	set_logfp(NULL, conf);

#ifndef HAVE_WIN32
	if(conf->mode==MODE_SERVER)
		setup_signals(oldmax_children, conf->max_children,
			oldmax_status_children, conf->max_status_children);
#endif

	// Do not try to change user or group after the first time.
	if(firsttime && chuser_and_or_chgrp(conf))
		return 1;

	return 0;
}

static int replace_conf_str(const char *newval, char **dest)
{
	if(newval)
	{
		if(*dest) free(*dest);
		if(!(*dest=strdup(newval)))
		{
			log_out_of_memory(__FUNCTION__);
			return -1;
		}
	}
	return 0;
}

static void usage(void)
{
	usage_server();
	usage_client();
}

#if defined(HAVE_WIN32)
#define main BurpMain
#endif
int main (int argc, char *argv[])
{
	int ret=1;
	int option=0;
	int daemon=1;
	int forking=1;
	int strip=0;
	struct lock *lock=NULL;
	struct conf *conf=NULL;
	int forceoverwrite=0;
	enum action act=ACTION_LIST;
	const char *backup=NULL;
	const char *restoreprefix=NULL;
	const char *regex=NULL;
	const char *browsefile=NULL;
	const char *browsedir=NULL;
	const char *conffile=get_conf_path();
	const char *orig_client=NULL;
	// The orig_client is the original client that the normal client
	// would like to restore from.
#ifndef HAVE_WIN32
	const char *sclient=NULL; // Status monitor client to view.
	int generate_ca_only=0;
#endif
	int vss_restore=1;
	int json=0;

	init_log(argv[0]);

	while((option=getopt(argc, argv, "a:b:c:C:d:ghfFil:nr:s:vxjz:?"))!=-1)
	{
		switch(option)
		{
			case 'a':
				if(!strncmp(optarg, "backup", 1))
					act=ACTION_BACKUP;
				else if(!strncmp(optarg, "timedbackup", 1))
					act=ACTION_BACKUP_TIMED;
				else if(!strncmp(optarg, "Timercheck", 1))
       					act=ACTION_TIMER_CHECK;
				else if(!strncmp(optarg, "restore", 1))
					act=ACTION_RESTORE;
				else if(!strncmp(optarg, "verify", 1))
					act=ACTION_VERIFY;
				else if(!strncmp(optarg, "list", 1))
					act=ACTION_LIST;
				else if(!strncmp(optarg, "List", 1))
					act=ACTION_LONG_LIST;
				else if(!strncmp(optarg, "status", 1))
					act=ACTION_STATUS;
				else if(!strncmp(optarg, "Status", 1))
					act=ACTION_STATUS_SNAPSHOT;
				else if(!strncmp(optarg, "estimate", 1))
					act=ACTION_ESTIMATE;
				// Start 'Delete' with a capital letter so that it is less
				// likely to be used accidently.
				else if(!strncmp(optarg, "Delete", 1))
					act=ACTION_DELETE;
				else if(!strncmp(optarg, "champchooser", 1))
					act=ACTION_CHAMP_CHOOSER;
				else
				{
					usage();
					goto end;
				}
				break;
			case 'b':
				backup=optarg;
				break;
			case 'c':
				conffile=optarg;
				break;
			case 'C':
				orig_client=optarg;
#ifndef HAVE_WIN32
				sclient=optarg;
#endif
				break;
			case 'd':
				restoreprefix=optarg; // for restores
				browsedir=optarg; // for lists
				break;
			case 'f':
				forceoverwrite=1;
				break;
			case 'F':
				daemon=0;
				break;
			case 'g':
#ifndef HAVE_WIN32
				generate_ca_only=1;
#endif
				break;
			case 'i':
				cmd_print_all();
				ret=0;
				goto end;
			case 'l':
				logp("-l <logfile> option obsoleted\n");
				break;
			case 'n':
				forking=0;
				break;
			case 'r':
				regex=optarg;
				break;
			case 's':
				strip=atoi(optarg);
				break;
			case 'v':
				printf("%s-%s\n", progname(), VERSION);
				ret=0;
				goto end;
			case 'x':
				vss_restore=0;
				break;
			case 'j':
				json=1;
				break;
			case 'z':
				browsefile=optarg;
				break;
			case 'h':
			case '?':
			default:
				usage();
				goto end;
		}
	}
	if(optind<argc)
	{
		usage();
		goto end;
	}

	if(!(conf=conf_alloc()))
		goto end;

	if(reload(conf, conffile,
	  1 /* first time */,
	  0 /* no oldmax_children setting */,
	  0 /* no oldmax_status_children setting */,
	  json)) goto end;

	if((act==ACTION_RESTORE || act==ACTION_VERIFY) && !backup)
	{
		logp("No backup specified. Using the most recent.\n");
		backup="0";
	}

	if(act==ACTION_DELETE && !backup)
	{
		logp("No backup specified for deletion.\n");
		goto end;
	}

	if(conf->mode==MODE_CLIENT)
	{
		if(orig_client && *orig_client)
		{
			if(!(conf->orig_client=strdup(orig_client)))
			{
				log_out_of_memory(__FUNCTION__);
				goto end;
			}
		}
	}

	if(conf->mode==MODE_SERVER
	  && (act==ACTION_STATUS
		|| act==ACTION_STATUS_SNAPSHOT
		|| act==ACTION_CHAMP_CHOOSER))
	{
		// These server modes need to run without getting the lock.
	}
	else
	{
		if(!(lock=lock_alloc_and_init(conf->lockfile)))
			goto end;
		lock_get(lock);
		switch(lock->status)
		{
			case GET_LOCK_GOT: break;
			case GET_LOCK_NOT_GOT:
				logp("Could not get lockfile.\n");
				logp("Another process is probably running,\n");
				goto end;
			case GET_LOCK_ERROR:
			default:
				logp("Could not get lockfile.\n");
				logp("Maybe you do not have permissions to write to %s.\n", conf->lockfile);
				goto end;
		}
	}

	conf->overwrite=forceoverwrite;
	conf->strip=strip;
	conf->forking=forking;
	conf->daemon=daemon;
	if(replace_conf_str(backup, &conf->backup)
	  || replace_conf_str(restoreprefix, &conf->restoreprefix)
	  || replace_conf_str(regex, &conf->regex)
	  || replace_conf_str(browsefile, &conf->browsefile)
	  || replace_conf_str(browsedir, &conf->browsedir))
		goto end;
	if(conf->mode==MODE_SERVER)
	{
#ifdef HAVE_WIN32
		logp("Sorry, server mode is not implemented for Windows.\n");
#else
		if(act==ACTION_STATUS || act==ACTION_STATUS_SNAPSHOT)
		{
			// We are running on the server machine, being a client
			// of the burp server, getting status information.
			ret=status_client_ncurses(conf, act, sclient);
		}
		else if(act==ACTION_CHAMP_CHOOSER)
		{
			// We are running on the server machine, wanting to
			// be a standalone champion chooser process.
			if(!sclient || !*sclient)
			{
				logp("No client name specified for standalone champion chooser process.\n");
				logp("Try using the '-C' option.\n");
				ret=1;
			}
			else
				ret=champ_chooser_server_standalone(conf,
					sclient);
		}
		else
			ret=server(conf, conffile, lock, generate_ca_only);
#endif
	}
	else
	{
		logp("before client\n");
		ret=client(conf, act, vss_restore, json);
		logp("after client\n");
	}

end:
	lock_release(lock);
	lock_free(&lock);
	conf_free(conf);
	return ret;
}
