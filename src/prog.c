#include "burp.h"
#include "base64.h"
#include "cmd.h"
#include "conf.h"
#include "conffile.h"
#include "client/main.h"
#include "handy.h"
#include "hexmap.h"
#include "lock.h"
#include "log.h"
#include "strlist.h"
#include "server/main.h"
#include "server/protocol1/bedup.h"
#include "server/protocol2/bsigs.h"
#include "server/protocol2/bsparse.h"
#include "server/protocol2/champ_chooser/champ_server.h"

static void usage_server(void)
{
#ifndef HAVE_WIN32
	printf("\nThe configuration file specifies whether %s runs in server or client mode.\n", PACKAGE_TARNAME);
	printf("\nServer usage: %s [options]\n", progname());
	printf("\n");
	printf(" Options:\n");
	printf("  -a c          Run as a stand-alone champion chooser.\n");
	printf("  -c <path>     Path to conf file (default: %s).\n", config_default_path());
	printf("  -d <path>     a single client in the status monitor.\n");
	printf("  -o <option>   Override a given configuration option (you can use this flag several times).\n");
	printf("  -F            Stay in the foreground.\n");
	printf("  -g            Generate initial CA certificates and exit.\n");
	printf("  -h|-?         Print this text and exit.\n");
	printf("  -i            Print index of symbols and exit.\n");
	printf("  -n            Do not fork any children (implies '-F').\n");
	printf("  -Q            Do not log to stdout\n");
	printf("  -t            Dry-run to test config file syntax.\n");
	printf("  -v            Log to stdout.\n");
	printf("  -V            Print version and exit.\n");
	printf("Options to use with '-a c':\n");
	printf("  -C <client>   Run as if forked via a connection from this client.\n");
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
	printf("                  delete: delete\n");
	printf("                  d: diff\n");
	printf("                  e: estimate\n");
	printf("                  l: list (this is the default when an action is not given)\n");
	printf("                  L: long list\n");
	printf("                  m: monitor interface\n");
	printf("                  r: restore\n");
#ifndef HAVE_WIN32
	printf("                  s: status monitor (ncurses)\n");
	printf("                  S: status monitor snapshot\n");
#endif
	printf("                  t: timed backup\n");
	printf("                  T: check backup timer, but do not actually backup\n");
	printf("                  v: verify\n");
	printf("  -b <number>    Backup number (default: the most recent backup).\n");
	printf("  -c <path>      Path to conf file (default: %s).\n", config_default_path());
	printf("  -d <directory> Directory to restore to, or directory to list.\n");
	printf("  -o <option>    Override a given configuration option (you can use this flag several times).\n");
	printf("  -f             Allow overwrite during restore.\n");
	printf("  -h|-?          Print this text and exit.\n");
	printf("  -i             Print index of symbols and exit.\n");
	printf("  -q <max secs>  Randomised delay of starting a timed backup.\n");
	printf("  -Q             Do not log to stdout\n");
	printf("  -r <regex>     Specify a regular expression.\n");
	printf("  -s <number>    Number of leading path components to strip during restore.\n");
	printf("  -t             Dry-run to test config file syntax.\n");
	printf("  -v             Log to stdout.\n");
	printf("  -V             Print version and exit.\n");
#ifdef HAVE_WIN32
	printf("  -x             Do not use the Windows VSS API when restoring.\n");
#else
	printf("  -x             Strip Windows VSS data when restoring.\n");
	printf("Options to use with '-a S':\n");
	printf("  -C <client>   Show a particular client.\n");
	printf("  -b <number>   Show listable files in a particular backup (requires -C).\n");
	printf("  -d <path>     Show a particular path in a backup (requires -C and -b).\n");
	printf("  -l <path>     Log file for the status monitor.\n");
	printf("  -z <file>     Dump a particular log file in a backup (requires -C and -b).\n");
#endif
	printf("\n");
#ifndef HAVE_WIN32
	printf(" See %s or the man page ('man %s') for usage examples\n",
		PACKAGE_URL, PACKAGE_TARNAME);
	printf(" and additional configuration options.\n\n");
#else
	printf(" See %s for usage examples and additional configuration\n",
		PACKAGE_TARNAME);
	printf(" options.\n\n");
#endif
}

int reload(struct conf **confs, const char *conffile, bool firsttime)
{
	if(!firsttime) logp("Reloading config\n");

	if(confs_init(confs)) return -1;

	if(conf_load_global_only(conffile, confs)) return -1;

	umask(get_mode_t(confs[OPT_UMASK]));

	// This will turn on syslogging which could not be turned on before
	// conf_load.
	log_fzp_set(NULL, confs);

#ifndef HAVE_WIN32
	if(get_e_burp_mode(confs[OPT_BURP_MODE])==BURP_MODE_SERVER)
		setup_signals();
#endif

	return 0;
}

static int replace_conf_str(struct conf *conf, const char *newval)
{
	if(!newval) return 0;
	return set_string(conf, newval);
}

static void usage(void)
{
	usage_server();
	usage_client();
}

static int parse_action(enum action *act, const char *optarg)
{
	if(!strncmp(optarg, "backup", 1))
		*act=ACTION_BACKUP;
	else if(!strncmp(optarg, "timedbackup", 1))
		*act=ACTION_BACKUP_TIMED;
	else if(!strncmp(optarg, "Timercheck", 1))
		*act=ACTION_TIMER_CHECK;
	else if(!strncmp(optarg, "restore", 1))
		*act=ACTION_RESTORE;
	else if(!strncmp(optarg, "verify", 1))
		*act=ACTION_VERIFY;
	else if(!strncmp(optarg, "list", 1))
		*act=ACTION_LIST;
	else if(!strncmp(optarg, "List", 1))
		*act=ACTION_LIST_LONG;
	else if(!strncmp(optarg, "status", 1))
		*act=ACTION_STATUS;
	else if(!strncmp(optarg, "Status", 1))
		*act=ACTION_STATUS_SNAPSHOT;
	else if(!strncmp(optarg, "estimate", 1))
		*act=ACTION_ESTIMATE;
	// Make them spell 'delete' out fully so that it is less likely to be
	// used accidently.
	else if(!strncmp_w(optarg, "delete"))
		*act=ACTION_DELETE;
	else if(!strncmp(optarg, "champchooser", 1))
		*act=ACTION_CHAMP_CHOOSER;
	else if(!strncmp(optarg, "diff", 1))
		*act=ACTION_DIFF;
	else if(!strncmp(optarg, "Diff", 1))
		*act=ACTION_DIFF_LONG;
	else if(!strncmp(optarg, "monitor", 1))
		*act=ACTION_MONITOR;
	else
	{
		usage();
		return -1;
	}
	return 0;
}

#ifndef HAVE_WIN32
static int run_champ_chooser(struct conf **confs)
{
	const char *orig_client=get_string(confs[OPT_ORIG_CLIENT]);
	if(orig_client && *orig_client)
		return champ_chooser_server_standalone(confs);
	logp("No client name given for standalone champion chooser process.\n");
	logp("Try using the '-C' option.\n");
	return 1;
}

static int server_modes(enum action act,
	const char *conffile, struct lock *lock, int generate_ca_only,
	struct conf **confs)
{
	switch(act)
	{
		case ACTION_CHAMP_CHOOSER:
			// We are running on the server machine, wanting to
			// be a standalone champion chooser process.
			return run_champ_chooser(confs);
		default:
			return server(confs, conffile, lock, generate_ca_only);
	}
}
#endif

static void random_delay(struct conf **confs)
{
	int delay;
	int randomise=get_int(confs[OPT_RANDOMISE]);
	if(!randomise) return;
	srand(getpid());
	delay=rand()%randomise;
	logp("Sleeping %d seconds\n", delay);
	sleep(delay);
}

static int run_test_confs(struct conf **confs, const char *client)
{
	int ret=-1;
	struct conf **cconfs=NULL;
	if(!client)
	{
		confs_dump(confs, 0);
		ret=0;
		goto end;
	}
	if(!(cconfs=confs_alloc()))
		goto end;
	confs_init(cconfs);
	if(set_string(cconfs[OPT_CNAME], client)
	  || set_string(cconfs[OPT_PEER_VERSION], PACKAGE_VERSION)
	  || conf_load_clientconfdir(confs, cconfs))
		goto end;
	confs_dump(cconfs, CONF_FLAG_CC_OVERRIDE|CONF_FLAG_INCEXC);

end:
	confs_free(&cconfs);
	return ret;
}

static struct lock *get_prog_lock(struct conf **confs)
{
	struct lock *lock=NULL;
	const char *lockfile=confs_get_lockfile(confs);
	if(!(lock=lock_alloc_and_init(lockfile)))
		goto error;
	lock_get(lock);
	switch(lock->status)
	{
		case GET_LOCK_GOT:
			return lock;
		case GET_LOCK_NOT_GOT:
			logp("Could not get lockfile.\n");
			logp("Another process is probably running.\n");
			goto error;
		case GET_LOCK_ERROR:
		default:
			logp("Could not get lockfile.\n");
			logp("Maybe you do not have permissions to write to %s.\n", lockfile);
			goto error;
	}
error:
	lock_free(&lock);
	return NULL;
}

#ifdef HAVE_WIN32
#define main RealMain
#endif
#ifndef UTEST
static
#endif
int real_main(int argc, char *argv[])
{
	int ret=1;
	int option=0;
	int daemon=1;
	int forking=1;
	int strip=0;
	int randomise=0;
	struct lock *lock=NULL;
	struct conf **confs=NULL;
	int forceoverwrite=0;
	enum action act=ACTION_LIST;
	const char *backup=NULL;
	const char *backup2=NULL;
	char *restoreprefix=NULL;
	char *stripfrompath=NULL;
	const char *regex=NULL;
	const char *browsefile=NULL;
	char *browsedir=NULL;
	const char *conffile=config_default_path();
	const char *orig_client=NULL;
	const char *logfile=NULL;
	// The orig_client is the original client that the normal client
	// would like to restore from.
#ifndef HAVE_WIN32
	int generate_ca_only=0;
#endif
	int vss_restore=1;
	int test_confs=0;
	enum burp_mode mode;
	struct strlist *cli_overrides=NULL;

	log_init(argv[0]);
#ifndef HAVE_WIN32
	if(!strcmp(prog, "bedup"))
		return run_bedup(argc, argv);
	if(!strcmp(prog, "bsigs"))
		return run_bsigs(argc, argv);
	if(!strcmp(prog, "bsparse"))
		return run_bsparse(argc, argv);
#endif

	while((option=getopt(argc, argv, "a:b:c:C:d:o:fFghijl:nq:Qr:s:tvVxz:?"))!=-1)
	{
		switch(option)
		{
			case 'a':
				if(parse_action(&act, optarg)) goto end;
				break;
			case 'b':
				// The diff command may have two backups
				// specified.
				if(!backup2 && backup) backup2=optarg;
				if(!backup) backup=optarg;
				break;
			case 'c':
				conffile=optarg;
				break;
			case 'C':
				orig_client=optarg;
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
				logfile=optarg;
				break;
			case 'n':
				forking=0;
				break;
			case 'o':
				strlist_add(&cli_overrides, optarg, 0);
				break;
			case 'q':
				randomise=atoi(optarg);
				break;
			case 'Q':
				strlist_add(&cli_overrides, "progress_counter=0", 0);
				strlist_add(&cli_overrides, "stdout=0", 0);
				break;
			case 'r':
				regex=optarg;
				break;
			case 's':
				strip=atoi(optarg);
				break;
			case 'v':
				strlist_add(&cli_overrides, "stdout=1", 0);
				break;
			case 'V':
				printf("%s-%s\n", progname(), PACKAGE_VERSION);
				ret=0;
				goto end;
			case 'x':
				vss_restore=0;
				break;
			case 't':
				test_confs=1;
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

	if(act==ACTION_MONITOR)
	{
		// Try to output everything in JSON.
		log_set_json(1);
		// Need to do this so that processes reading stdout get the
		// result of the printfs of logp straight away.
		setvbuf(stdout, NULL, _IONBF, 0);
	}

	conf_set_cli_overrides(cli_overrides);
	if(!(confs=confs_alloc()))
		goto end;

	if(reload(confs, conffile, 1))
		goto end;

	// Dry run to test config file syntax.
	if(test_confs)
	{
		ret=run_test_confs(confs, orig_client);
		goto end;
	}

	if(!backup) switch(act)
	{
		case ACTION_DELETE:
			logp("No backup specified for deletion.\n");
			goto end;
		case ACTION_RESTORE:
		case ACTION_VERIFY:
		case ACTION_DIFF:
		case ACTION_DIFF_LONG:
			logp("No backup specified. Using the most recent.\n");
			backup="0";
		default:
			break;
	}
	if(!backup2) switch(act)
	{
		case ACTION_DIFF:
		case ACTION_DIFF_LONG:
			logp("No second backup specified. Using file system scan.\n");
			backup2="n"; // For 'next'.
		default:
			break;
	}

	// The logfile option is only used for the status client stuff.
	if(logfile
	  && (act!=ACTION_STATUS
		&& act!=ACTION_STATUS_SNAPSHOT))
			logp("-l <logfile> option obsoleted\n");

	if(orig_client
	  && *orig_client
	  && set_string(confs[OPT_ORIG_CLIENT], orig_client))
		goto end;

	// The random delay needs to happen before the lock is got, otherwise
	// you would never be able to use burp by hand.
	if(randomise) set_int(confs[OPT_RANDOMISE], randomise);
	mode=get_e_burp_mode(confs[OPT_BURP_MODE]);
	if(mode==BURP_MODE_CLIENT
	  && (act==ACTION_BACKUP_TIMED || act==ACTION_TIMER_CHECK))
		random_delay(confs);

	if(mode==BURP_MODE_SERVER)
	{
		switch(act)
		{
			case ACTION_CHAMP_CHOOSER:
				// Need to run without getting the lock.
				break;
			default:
				if(!(lock=get_prog_lock(confs)))
					goto end;
				break;
		}
	}
	else if(mode==BURP_MODE_CLIENT)
	{
		switch(act)
		{
			case ACTION_BACKUP:
			case ACTION_BACKUP_TIMED:
			case ACTION_TIMER_CHECK:
				// Need to get the lock.
				if(!(lock=get_prog_lock(confs)))
					goto end;
				break;
			default:
				break;
		}
	}

	// Change privileges after having got the lock, for convenience.
	if(chuser_and_or_chgrp(
		get_string(confs[OPT_USER]), get_string(confs[OPT_GROUP])))
			return -1;

	set_int(confs[OPT_OVERWRITE], forceoverwrite);
	set_int(confs[OPT_STRIP], strip);
	set_int(confs[OPT_FORK], forking);
	set_int(confs[OPT_DAEMON], daemon);

	strip_trailing_slashes(&restoreprefix);
	strip_trailing_slashes(&browsedir);
	if(replace_conf_str(confs[OPT_BACKUP], backup)
	  || replace_conf_str(confs[OPT_BACKUP2], backup2)
	  || replace_conf_str(confs[OPT_RESTOREPREFIX], restoreprefix)
	  || replace_conf_str(confs[OPT_STRIP_FROM_PATH], stripfrompath)
	  || replace_conf_str(confs[OPT_REGEX], regex)
	  || replace_conf_str(confs[OPT_BROWSEFILE], browsefile)
	  || replace_conf_str(confs[OPT_BROWSEDIR], browsedir)
	  || replace_conf_str(confs[OPT_MONITOR_LOGFILE], logfile))
		goto end;

	base64_init();
	hexmap_init();

	if(mode==BURP_MODE_SERVER)
	{
#ifdef HAVE_WIN32
		logp("Sorry, server mode is not implemented for Windows.\n");
#else
		ret=server_modes(act,
			conffile, lock, generate_ca_only, confs);
#endif
	}
	else
	{
		ret=client(confs, act, vss_restore);
	}

end:
	lock_release(lock);
	lock_free(&lock);
	confs_free(&confs);
	strlists_free(&cli_overrides);
	return ret;
}

#ifndef UTEST
int main(int argc, char *argv[])
{
	return real_main(argc, argv);
}
#endif
