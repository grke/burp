#include "../../burp.h"
#include "../../attribs.h"
#include "../../base64.h"
#include "../../conffile.h"
#include "../../cstat.h"
#include "../../fsops.h"
#include "../../fzp.h"
#include "../../handy.h"
#include "../../hexmap.h"
#include "../../iobuf.h"
#include "../../lock.h"
#include "../../log.h"
#include "../../strlist.h"
#include "../../protocol2/blk.h"
#include "../bu_get.h"
#include "../protocol2/backup_phase4.h"
#include "../sdirs.h"
#include "bsigs.h"
#include "clist.h"
#include "champ_chooser/champ_chooser.h"
#include "sparse_min.h"

static struct lock *sparse_lock=NULL;
static struct cstat *clist=NULL;

static int usage(void)
{
	logfmt("\nUsage: %s [options] <path to dedup_group>\n", prog);
	logfmt("\n");
	logfmt(" Options:\n");
	logfmt("  -c <path>  Path to config file (default: %s).\n",
		config_default_path());
	logfmt("\n");
	return 1;
}

static void release_locks(struct cstat *clist)
{
	struct cstat *c;
	struct sdirs *s;
	for(c=clist; c; c=c->next)
	{
		s=(struct sdirs *)c->sdirs;
		if(!s) continue;
		lock_release(s->lock_storage_for_write);
		logp("released: %s\n", c->name);
	}
	lock_release(sparse_lock);
	lock_free(&sparse_lock);
	logp("released: sparse index\n");
}

static void sighandler(__attribute__ ((unused)) int signum)
{
	release_locks(clist);
	exit(1);
}

static struct sdirs *get_sdirs(struct conf **conf)
{
	struct sdirs *sdirs=NULL;
	if(!(sdirs=sdirs_alloc())
	  || sdirs_init_from_confs(sdirs, conf))
		sdirs_free(&sdirs);
	return sdirs;
}

static int parse_directory(const char *arg,
	char **directory, char **dedup_group)
{
	char *cp;
	if(!(*directory=strdup_w(arg, __func__)))
		goto error;
	strip_trailing_slashes(directory);
	if(!(cp=strrchr(*directory, '/')))
	{
		logp("Could not parse directory '%s'\n", *directory);
		goto error;
	}
	*cp='\0';
	if(!(*dedup_group=strdup_w(cp+1, __func__)))
		goto error;
	if(!*directory || !*dedup_group)
		goto error;
	return 0;
error:
	free_w(directory);
	free_w(dedup_group);
	return -1;
}

static struct conf **load_conf(const char *configfile,
	const char *directory, const char *dedup_group)
{
	struct conf **conf=NULL;
	if(!(conf=confs_alloc())
	  || confs_init(conf)
	  || conf_load_global_only(configfile, conf)
	  || set_string(conf[OPT_CNAME], "fake")
	  || set_string(conf[OPT_DIRECTORY], directory)
	  || set_string(conf[OPT_DEDUP_GROUP], dedup_group)
	  || set_protocol(conf, PROTO_2))
		confs_free(&conf);
	return conf;
}

static void setup_sighandler(void)
{
	signal(SIGABRT, &sighandler);
	signal(SIGTERM, &sighandler);
	signal(SIGINT, &sighandler);
}

static int get_sparse_lock(const char *sparse)
{
	if(!(sparse_lock=try_to_get_sparse_lock(sparse)))
	{
		logp("Could not get sparse lock\n");
		return -1;
	}
	return 0;
}

static int get_client_locks(struct cstat *clist)
{
	struct cstat *c;
	struct sdirs *s;
	for(c=clist; c; c=c->next)
	{
		s=(struct sdirs *)c->sdirs;
		if(mkpath(&s->lock_storage_for_write->path, s->lockdir))
		{
			logp("problem with lock directory: %s\n", s->lockdir);
			return -1;
		}

		lock_get(s->lock_storage_for_write);
		switch(s->lock_storage_for_write->status)
		{
			case GET_LOCK_GOT:
				logp("locked: %s\n", c->name);
				break;
			case GET_LOCK_NOT_GOT:
				logp("Unable to get lock for client %s\n",
					c->name);
				return -1;
			case GET_LOCK_ERROR:
			default:
				logp("Problem with lock file: %s\n",
					s->lock_storage_for_write->path);
				return -1;
		}
	}
	return 0;
}

static int merge_in_client_sparse_indexes(struct cstat *c,
	const char *global_sparse)
{
	int ret=-1;
	char *sparse=NULL;
	struct bu *b=NULL;
	struct bu *bu_list=NULL;
	struct sdirs *s=(struct sdirs *)c->sdirs;

	if(bu_get_list(s, &bu_list))
		goto end;
	for(b=bu_list; b; b=b->next)
	{
		free_w(&sparse);
		if(!(sparse=prepend_s(b->path, "manifest/sparse")))
			goto end;
		logp("merge: %s\n", sparse);
		if(merge_into_global_sparse(sparse,
			global_sparse, sparse_lock))
				goto end;
	}
	ret=0;
end:
	bu_list_free(&bu_list);
	free_w(&sparse);
	return ret;
}

static int merge_in_all_sparse_indexes(const char *global_sparse)
{
	struct cstat *c;

	if(!is_reg_lstat(global_sparse)
	  && unlink(global_sparse))
	{
		logp("Could not delete %s: %s\n",
			global_sparse, strerror(errno));
		return -1;
	}

	for(c=clist; c; c=c->next)
		if(merge_in_client_sparse_indexes(c, global_sparse))
			return -1;
	return 0;
}

int run_bsparse(int argc, char *argv[])
{
	int ret=1;
	int option;
	char *directory=NULL;
	char *dedup_group=NULL;
	const char *configfile=NULL;
	struct sdirs *sdirs=NULL;
	struct conf **conf=NULL;

	base64_init();
	configfile=config_default_path();

	while((option=getopt(argc, argv, "c:Vh?"))!=-1)
	{
		switch(option)
		{
			case 'c':
				configfile=optarg;
				break;
			case 'V':
				logfmt("%s-%s\n", prog, PACKAGE_VERSION);
				return 0;
			case 'h':
			case '?':
				return usage();
		}
	}

	if(optind>=argc || optind<argc-1)
		return usage();

	if(parse_directory(argv[optind], &directory, &dedup_group))
		goto end;

	logp("config file: %s\n", configfile);
	logp("directory: %s\n", directory);
	logp("dedup_group: %s\n", dedup_group);

	if(!(conf=load_conf(configfile, directory, dedup_group))
	  || !(sdirs=get_sdirs(conf)))
		goto end;

	logp("clients: %s\n", sdirs->clients);
	logp("sparse file: %s\n", sdirs->global_sparse);

	setup_sighandler();

	if(get_sparse_lock(sdirs->global_sparse))
		goto end;

	if(get_client_list(&clist, sdirs->clients, conf))
	{
		logp("Did not find any client directories\n");
		goto end;
	}

	if(get_client_locks(clist))
		goto end;

	if(merge_in_all_sparse_indexes(sdirs->global_sparse))
		goto end;

	if(sparse_minimise(conf, sdirs->global_sparse, sparse_lock, clist))
		goto end;

	ret=0;
end:
	release_locks(clist);
	sdirs_free(&sdirs);
	free_w(&directory);
	free_w(&dedup_group);
	confs_free(&conf);
	clist_free(&clist);
	return ret;
}
