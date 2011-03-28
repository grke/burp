#include "burp.h"
#include "prog.h"
#include "msg.h"
#include "lock.h"
#include "status_client.h"

static void usage(void)
{
	logp("usage: %s <options>\n", progname());
}

#if defined(HAVE_WIN32)
#define main BurpMain
#endif
int main (int argc, char *argv[])
{
	int ret=0;
	int option=0;
	int forking=1;
	int gotlock=0;
	struct config conf;
	int forceoverwrite=0;
	enum action act=ACTION_LIST;
	const char *backup=NULL;
	const char *restoreprefix=NULL;
	const char *regex=NULL;
	const char *cstatus=NULL;
#ifdef HAVE_WIN32
	const char *configfile="C:/Program Files/Burp/burp.conf";
#else
	const char *configfile="/etc/burp/burp.conf";
#endif

	init_log(argv[0]);

	while((option=getopt(argc, argv, "a:b:c:d:hfnr:s:v?"))!=-1)
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
			case 'n':
				forking=0;
				break;
			case 'r':
				regex=optarg;
				break;
			case 's':
				// For status mode, specify a particular
				// client (without this, you get status
				// for all clients).
				cstatus=optarg;
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

	if((act==ACTION_RESTORE || act==ACTION_VERIFY) && !backup)
	{
		logp("No backup specified. Using the most recent.\n");
		backup="0";
	}

	init_config(&conf);
	if(load_config(configfile, &conf, 1)) return 1;

	if(conf.mode==MODE_SERVER && act==ACTION_STATUS)
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
		if(act==ACTION_STATUS)
		{
			// We are running on the server machine, being a client
			// of the burp server, getting status information.
			ret=status_client(&conf, cstatus);
		}
		else
			ret=server(&conf, configfile, forking);
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
	return ret;
}
