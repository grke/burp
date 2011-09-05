#include "burp.h"
#include "prog.h"
#include "msg.h"
#include "lock.h"
#include "handy.h"
#include "status_client.h"

static char *get_config_path(void)
{
	static char path[256]="";
#ifdef HAVE_WIN32
	snprintf(path, sizeof(path), "%s", "C:/Program Files/Burp/burp.conf");
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
	printf("  -a s          Run the status monitor.\n");
	printf("  -c <path>     Path to config file (default: %s).\n", get_config_path());
	printf("  -F            Stay in the foreground.\n");
	printf("  -h|-?         Print this text and exit.\n");
	printf("  -l <path>     Path to log file.\n");
	printf("  -n            Do not fork any children (implies '-F').\n");
	printf("  -v            Print version and exit.\n");
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
	printf("                  l: list (this is the default when an action is not given)\n");
	printf("                  L: long list\n");
	printf("                  r: restore\n");
	printf("                  t: timed backup\n");
	printf("                  v: verify\n");
	printf("  -b <number>    Backup number (default: the most recent backup)\n");
	printf("  -c <path>      Path to config file (default: %s).\n", get_config_path());
	printf("  -d <directory> Directory to restore to.\n");
	printf("  -f             Allow overwrite during restore.\n");
	printf("  -h|-?          Print this text and exit.\n");
	printf("  -l <path>      Path to log file.\n");
	printf("  -r <regex>     Specify a regular expression.\n");
	printf("  -v             Print version and exit.\n");
	printf("\n");
#ifndef HAVE_WIN32
	printf(" See http://burp.grke.net/ or the man page ('man burp') for usage examples\n");
	printf(" and additional configuration options.\n\n");
#else
	printf(" See http://burp.grke.net/ for usage examples and additional configuration\n");
	printf(" options.\n\n");
#endif
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
	int ret=0;
	int option=0;
	int daemon=1;
	int forking=1;
	int gotlock=0;
	char *logfile=NULL;
	struct config conf;
	int forceoverwrite=0;
	enum action act=ACTION_LIST;
	const char *backup=NULL;
	const char *restoreprefix=NULL;
	const char *regex=NULL;
	FILE *fp=NULL;
	const char *configfile=get_config_path();

	init_log(argv[0]);

	while((option=getopt(argc, argv, "a:b:c:d:hfFnr:l:v?"))!=-1)
	{
		switch(option)
		{
			case 'a':
				if(!strncmp(optarg, "backup", 1))
					act=ACTION_BACKUP;
				else if(!strncmp(optarg, "timedbackup", 1))
					act=ACTION_BACKUP_TIMED;
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
				else
				{
					usage();
					return 1;
				}
				break;
			case 'b':
				backup=optarg;
				break;
			case 'c':
				configfile=optarg;
				break;
			case 'd':
				restoreprefix=optarg;
				break;
			case 'f':
				forceoverwrite=1;
				break;
			case 'F':
				daemon=0;
				break;
			case 'n':
				forking=0;
				break;
			case 'r':
				regex=optarg;
				break;
			case 'l':
				logfile=optarg;
				break;
			case 'v':
				printf("%s-%s\n", progname(), VERSION);
				return 0;
			case 'h':
			case '?':
			default:
				usage();
				return 1;
				break;
		}
	}
	if(optind<argc)
	{
		usage();
		return 1;
	}

#ifndef HAVE_WIN32
	if(server_reload(&conf, configfile, &logfile,
	  1 /* first time */, 0 /* no old maxchildren setting */)) return 1;
#endif

	if((act==ACTION_RESTORE || act==ACTION_VERIFY) && !backup)
	{
		logp("No backup specified. Using the most recent.\n");
		backup="0";
	}

	if(conf.mode==MODE_SERVER
	  && (act==ACTION_STATUS || act==ACTION_STATUS_SNAPSHOT))
	{
		// Server status mode needs to run without getting the lock.
	}
	else
	{
		if(get_lock(conf.lockfile))
		{
			logp("Could not get lockfile.\n");
			logp("Another process is probably running,\n");
			logp("or you do not have permissions to write to %s.\n",
				conf.lockfile);
			return 1;
		}
		gotlock++;
	}

	if(conf.mode==MODE_SERVER)
	{
#ifdef HAVE_WIN32
		logp("Sorry, server mode is not implemented for Windows.\n");
#else
		if(act==ACTION_STATUS || act==ACTION_STATUS_SNAPSHOT)
		{
			// We are running on the server machine, being a client
			// of the burp server, getting status information.
			ret=status_client(&conf, act);
		}
		else
			ret=server(&conf, configfile,
				forking, daemon, &logfile);
#endif
	}
	else
	{
		logp("before client\n");
		ret=client(&conf, act, backup,
			restoreprefix, regex, forceoverwrite);
		logp("after client\n");
	}

	if(gotlock) unlink(conf.lockfile);
	free_config(&conf);

	// If there was no forking, logfp ends up getting closed before this
	// and will segfault if we try to do it again.
	if(fp && forking) fclose(fp);
	return ret;
}
