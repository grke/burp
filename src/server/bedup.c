#include "../burp.h"
#include "../alloc.h"
#include "../conf.h"
#include "../conffile.h"
#include "../handy.h"
#include "../fsops.h"
#include "../fzp.h"
#include "../lock.h"
#include "../log.h"
#include "../prepend.h"
#include "../strlist.h"
#include "bedup.h"

#include <uthash.h>

#define LOCKFILE_NAME		"lockfile"
#define BEDUP_LOCKFILE_NAME	"lockfile.bedup"

#define DEF_MAX_LINKS		10000

static int makelinks=0;
static int deletedups=0;

static uint64_t savedbytes=0;
static uint64_t count=0;
static int ccount=0;

static struct lock *locklist=NULL;

static int verbose=0;

static unsigned int maxlinks=DEF_MAX_LINKS;
static char ext[16]="";

typedef struct file file_t;

struct file
{
	char *path;
	dev_t dev;
	ino_t ino;
	nlink_t nlink;
	uint64_t full_cksum;
	uint64_t part_cksum;
	file_t *next;
};

struct mystruct
{
	off_t st_size;
	file_t *files;
	UT_hash_handle hh;
};

struct mystruct *myfiles=NULL;

static struct mystruct *find_key(off_t st_size)
{
	struct mystruct *s;

	HASH_FIND_INT(myfiles, &st_size, s);
	return s;
}

static int add_file(struct mystruct *s, struct file *f)
{
	struct file *newfile;
	if(!(newfile=(struct file *)malloc_w(sizeof(struct file), __func__)))
		return -1;
	memcpy(newfile, f, sizeof(struct file));
	f->path=NULL;
	newfile->next=s->files;
	s->files=newfile;
	return 0;
}

static int add_key(off_t st_size, struct file *f)
{
	struct mystruct *s;

	if(!(s=(struct mystruct *)malloc_w(sizeof(struct mystruct), __func__)))
		return -1;
	s->st_size=st_size;
	s->files=NULL;
	if(add_file(s, f)) return -1;
//printf("HASH ADD %d\n", st_size);
	HASH_ADD_INT(myfiles, st_size, s);
	return 0;
}

static void file_free_content(struct file *file)
{
	if(!file) return;
	free_w(&file->path);
}

static void file_free(struct file **file)
{
	if(!file || !*file) return;
	file_free_content(*file);
	free_v((void **)file);
}

static void files_free(struct file **files)
{
	struct file *f;
	struct file *fhead;
	if(!files || !*files) return;
	fhead=*files;
	while(fhead)
	{
		f=fhead;
		fhead=fhead->next;
		file_free(&f);
	}
}

static void mystruct_free_content(struct mystruct *mystruct)
{
	if(!mystruct) return;
	files_free(&mystruct->files);
}

static void mystruct_free(struct mystruct **mystruct)
{
	if(!mystruct || !*mystruct) return;
	mystruct_free_content(*mystruct);
	free_v((void **)mystruct);
}

static void mystruct_delete_all(void)
{
	struct mystruct *tmp;
	struct mystruct *mystruct;

	HASH_ITER(hh, myfiles, mystruct, tmp)
	{
		HASH_DEL(myfiles, mystruct);
		mystruct_free(&mystruct);
	}
	myfiles=NULL;
}

#define FULL_CHUNK	4096

static int full_match(struct file *o, struct file *n,
	struct fzp **ofp, struct fzp **nfp)
{
	size_t ogot;
	size_t ngot;
	unsigned int i=0;
	static char obuf[FULL_CHUNK];
	static char nbuf[FULL_CHUNK];

	if(*ofp) fzp_seek(*ofp, 0, SEEK_SET);
	else if(!(*ofp=fzp_open(o->path, "rb")))
	{
		// Blank this entry so that it can be ignored from
		// now on.
		free_w(&o->path);
		return 0;
	}

	if(*nfp) fzp_seek(*nfp, 0, SEEK_SET);
	else if(!(*nfp=fzp_open(n->path, "rb"))) return 0;

	while(1)
	{
		ogot=fzp_read(*ofp, obuf, FULL_CHUNK);
		ngot=fzp_read(*nfp, nbuf, FULL_CHUNK);
		if(ogot!=ngot) return 0;
		for(i=0; i<ogot; i++)
			if(obuf[i]!=nbuf[i]) return 0;
		if(ogot<FULL_CHUNK) break;
	}

	return 1;
}

#define PART_CHUNK	1024

static int get_part_cksum(struct file *f, struct fzp **fzp)
{
	MD5_CTX md5;
	int got=0;
	static char buf[PART_CHUNK];
	unsigned char checksum[MD5_DIGEST_LENGTH+1];

	if(*fzp) fzp_seek(*fzp, 0, SEEK_SET);
	else if(!(*fzp=fzp_open(f->path, "rb")))
	{
		f->part_cksum=0;
		return 0;
	}

	if(!MD5_Init(&md5))
	{
		logp("MD5_Init() failed\n");
		return -1;
	}

	got=fzp_read(*fzp, buf, PART_CHUNK);

	if(!MD5_Update(&md5, buf, got))
	{
		logp("MD5_Update() failed\n");
		return -1;
	}

	if(!MD5_Final(checksum, &md5))
	{
		logp("MD5_Final() failed\n");
		return -1;
	}

	memcpy(&(f->part_cksum), checksum, sizeof(unsigned));

	// Try for a bit of efficiency - no need to calculate the full checksum
	// again if we already read the whole file.
	if(got<PART_CHUNK) f->full_cksum=f->part_cksum;

	return 0;
}

static int get_full_cksum(struct file *f, struct fzp **fzp)
{
	size_t s=0;
	MD5_CTX md5;
	static char buf[FULL_CHUNK];
	unsigned char checksum[MD5_DIGEST_LENGTH+1];

	if(*fzp) fzp_seek(*fzp, 0, SEEK_SET);
	else if(!(*fzp=fzp_open(f->path, "rb")))
	{
		f->full_cksum=0;
		return 0;
	}

	if(!MD5_Init(&md5))
	{
		logp("MD5_Init() failed\n");
		return -1;
	}

	while((s=fzp_read(*fzp, buf, FULL_CHUNK))>0)
	{
		if(!MD5_Update(&md5, buf, s))
		{
			logp("MD5_Update() failed\n");
			return -1;
		}
		if(s<FULL_CHUNK) break;
	}

	if(!MD5_Final(checksum, &md5))
	{
		logp("MD5_Final() failed\n");
		return -1;
	}

	memcpy(&(f->full_cksum), checksum, sizeof(unsigned));

	return 0;
}

/* Make it atomic by linking to a temporary file, then moving it into place. */
static int do_hardlink(struct file *o, struct file *n)
{
	int ret=-1;
	char *tmppath=NULL;
	if(!(tmppath=prepend(o->path, ext)))
	{
		log_out_of_memory(__func__);
		goto end;
	}
	if(link(n->path, tmppath))
	{
		logp("Could not hardlink %s to %s: %s\n", tmppath, n->path,
			strerror(errno));
		goto end;
	}
	if((ret=do_rename(tmppath, o->path)))
	{
		// 'man 2 rename', says it should be safe to unlink tmppath:
		// "If newpath exists but the operation fails for some reason,
		// rename() guarantees to leave an instance of newpath in
		// place."
		if(unlink(tmppath))
			logp("Could not unlink %s\n", tmppath);
		goto end;
	}
	ret=0;
end:
	free_w(&tmppath);
	return ret;
}

static void reset_old_file(struct file *oldfile, struct file *newfile,
	struct stat *info)
{
	//printf("reset %s with %s %d\n", oldfile->path, newfile->path,
	//	info->st_nlink);
	struct file *next;

	next=oldfile->next;
	free_w(&oldfile->path);
	memcpy(oldfile, newfile, sizeof(struct file));
	oldfile->next=next;
	newfile->path=NULL;
}

static int check_files(struct mystruct *find, struct file *newfile,
	struct stat *info)
{
	int found=0;
	struct fzp *nfp=NULL;
	struct fzp *ofp=NULL;
	struct file *f=NULL;

	for(f=find->files; f; f=f->next)
	{
//printf("  against: '%s'\n", f->path);
		if(!f->path)
		{
			// If the full_match() function fails to open oldfile
			// (which could happen if burp deleted some old
			// directories), it will free path and set it to NULL.
			// Skip entries like this.
			continue;
		}
		if(newfile->dev!=f->dev)
		{
			// Different device.
			continue;
		}
		if(newfile->ino==f->ino)
		{
			// Same device, same inode, therefore these two files
			// are hardlinked to each other already.
			found++;
			break;
		}
		if(newfile->nlink>=maxlinks) {
			// This new file file has enough links. Just leave it
			// as it is to avoid undoing all these hardlinks.
			found++;
			break;
		}
		if((!newfile->part_cksum && get_part_cksum(newfile, &nfp))
		  || (!f->part_cksum && get_part_cksum(f, &ofp)))
		{
			// Some error with md5sums Give up.
			return -1;
		}
		if(newfile->part_cksum!=f->part_cksum)
		{
			fzp_close(&ofp);
			continue;
		}
		//printf("  %s, %s\n", find->files->path, newfile->path);
		//printf("  part cksum matched\n");

		if((!newfile->full_cksum && get_full_cksum(newfile, &nfp))
		  || (!f->full_cksum && get_full_cksum(f, &ofp)))
		{
			// Some error with md5sums Give up.
			return -1;
		}
		if(newfile->full_cksum!=f->full_cksum)
		{
			fzp_close(&ofp);
			continue;
		}

		//printf("  full cksum matched\n");
		if(!full_match(newfile, f, &nfp, &ofp))
		{
			fzp_close(&ofp);
			continue;
		}
		//printf("  full match\n");
		//printf("%s, %s\n", find->files->path, newfile->path);

		// If there are already enough links to this file, replace
		// our memory of it with the new file so that files later on
		// can link to the new one. 
		if(f->nlink>=maxlinks)
		{
			// Just need to reset the path name and the number
			// of links, and pretend that it was found otherwise
			// NULL newfile will get added to the memory.
			reset_old_file(f, newfile, info);
			found++;
			break;
		}

		found++;
		count++;

		if(verbose) printf("%s\n", newfile->path);

		// Now hardlink it.
		if(makelinks)
		{
			if(do_hardlink(newfile, f))
			{
				count--;
				return -1;
			}
			f->nlink++;
			// Only count bytes as saved if we
			// removed the last link.
			if(newfile->nlink==1)
				savedbytes+=info->st_size;
		}
		else if(deletedups)
		{
			if(unlink(newfile->path))
			{
				logp("Could not delete %s: %s\n",
					newfile->path, strerror(errno));
			}
			else
			{
				// Only count bytes as saved if we removed the
				// last link.
				if(newfile->nlink==1)
					savedbytes+=info->st_size;
			}
		}
		else
		{
			// To be able to tell how many bytes
			// are saveable.
			savedbytes+=info->st_size;
		}

		break;
	}
	fzp_close(&nfp);
	fzp_close(&ofp);

	if(found)
	{
		free_w(&newfile->path);
		return 0;
	}

	if(add_file(find, newfile)) return -1;

	return 0;
}

static int looks_like_ours(const char *basedir)
{
	int ret=-1;
	char *tmp=NULL;
	if(!(tmp=prepend_s(basedir, "current")))
	{
		log_out_of_memory(__func__);
		goto end;
	}
	// If there is a 'current' symlink here, we think it looks like a
	// one of our storage directories.
	if(is_lnk_lstat(tmp)>0)
	{
		ret=1;
		goto end;
	}
	ret=0;
end:
	free_w(&tmp);
	return ret;
}

static int get_link(const char *basedir, const char *lnk, char real[], size_t r)
{
	readlink_w_in_dir(basedir, lnk, real, r);
	// Strip any trailing slash.
	if(real[strlen(real)-1]=='/')
		real[strlen(real)-1]='\0';
	return 0;
}

static int level_exclusion(int level, const char *fname,
	const char *working, const char *finishing)
{
	if(level==0)
	{
		/* Be careful not to try to dedup the lockfiles.
		   The lock actually gets lost if you open one to do a
		   checksum
		   and then close it. This caused me major headaches to
		   figure out. */
		if(!strcmp(fname, LOCKFILE_NAME)
		  || !strcmp(fname, BEDUP_LOCKFILE_NAME))
			return 1;

		/* Skip places where backups are going on. */
		if(!strcmp(fname, working)
		  || !strcmp(fname, finishing))
			return 1;

		if(!strcmp(fname, "deleteme"))
			return 1;
	}
	else if(level==1)
	{
		// Do not dedup stuff that might be appended to later.
		if(!strncmp(fname, "log", strlen("log"))
		  || !strncmp(fname, "verifylog", strlen("verifylog"))
		  || !strncmp(fname, "restorelog", strlen("restorelog")))
			return 1;
	}
	return 0;
}

// Return 0 for directory processed, -1 for error, 1 for not processed.
static int process_dir(const char *oldpath, const char *newpath,
	int burp_mode, int level)
{
	int ret=-1;
	DIR *dirp=NULL;
	char *path=NULL;
	struct stat info;
	struct dirent *dirinfo=NULL;
	struct file newfile;
	struct mystruct *find=NULL;
	static char working[256]="";
	static char finishing[256]="";

	newfile.path=NULL;

	if(!(path=prepend_s(oldpath, newpath))) goto end;

	if(burp_mode && level==0)
	{
		if(get_link(path, "working", working, sizeof(working))
		  || get_link(path, "finishing", finishing, sizeof(finishing)))
			goto end;
		if(!looks_like_ours(path))
		{
			logp("%s does not look like one of our storage directories - skipping\n", path);
			ret=1;
			goto end;
		}
	}

	if(!(dirp=opendir(path)))
	{
		logp("Could not opendir '%s': %s\n", path, strerror(errno));
		ret=1;
		goto end;
	}
	while((dirinfo=readdir(dirp)))
	{
		if(!strcmp(dirinfo->d_name, ".")
		  || !strcmp(dirinfo->d_name, ".."))
			continue;

		//printf("try %s\n", dirinfo->d_name);

		if(burp_mode
		  && level_exclusion(level, dirinfo->d_name,
			working, finishing))
				continue;

		free_w(&newfile.path);
		if(!(newfile.path=prepend_s(path, dirinfo->d_name)))
			goto end;

		if(lstat(newfile.path, &info))
			continue;

		if(S_ISDIR(info.st_mode))
		{
			if(process_dir(path, dirinfo->d_name,
				burp_mode, level+1))
					goto end;
			continue;
		}
		else if(!S_ISREG(info.st_mode)
		  || !info.st_size) // ignore zero-length files
			continue;

		newfile.dev=info.st_dev;
		newfile.ino=info.st_ino;
		newfile.nlink=info.st_nlink;
		newfile.full_cksum=0;
		newfile.part_cksum=0;
		newfile.next=NULL;

		if((find=find_key(info.st_size)))
		{
			//printf("check %d: %s\n", info.st_size, newfile.path);
			if(check_files(find, &newfile, &info))
				goto end;
		}
		else
		{
			//printf("add: %s\n", newfile.path);
			if(add_key(info.st_size, &newfile))
				goto end;
		}
	}
	ret=0;
end:
	if(dirp) closedir(dirp);
	free_w(&newfile.path);
	free_w(&path);
	return ret;
}

static void sighandler(__attribute__ ((unused)) int signum)
{
	locks_release_and_free(&locklist);
	exit(1);
}

static int is_regular_file(const char *clientconfdir, const char *file)
{
	struct stat statp;
	char *fullpath=NULL;
	if(!(fullpath=prepend_s(clientconfdir, file)))
		return 0;
	if(lstat(fullpath, &statp))
	{
		free_w(&fullpath);
		return 0;
	}
	free_w(&fullpath);
	return S_ISREG(statp.st_mode);
}

static int in_group(struct strlist *grouplist, const char *dedup_group)
{
	struct strlist *g;

	for(g=grouplist; g; g=g->next)
		if(!strcmp(g->path, dedup_group)) return 1;

	return 0;
}

static int iterate_over_clients(struct conf **globalcs,
	struct strlist *grouplist)
{
	int ret=0;
	DIR *dirp=NULL;
	struct conf **cconfs=NULL;
	struct dirent *dirinfo=NULL;
	const char *globalclientconfdir=get_string(globalcs[OPT_CLIENTCONFDIR]);

	if(!(cconfs=confs_alloc())) return -1;
	if(confs_init(cconfs)) return -1;

	if(!(dirp=opendir(globalclientconfdir)))
	{
		logp("Could not opendir '%s': %s\n",
			globalclientconfdir, strerror(errno));
		return 0;
	}
	while((dirinfo=readdir(dirp)))
	{
		char *lockfile=NULL;
		char *lockfilebase=NULL;
		char *client_lockdir=NULL;
		struct lock *lock=NULL;

		if(dirinfo->d_ino==0
		  || !cname_valid(dirinfo->d_name)
		  || !is_regular_file(globalclientconfdir, dirinfo->d_name))
			continue;

		confs_free_content(cconfs);
		if(confs_init(cconfs)) return -1;

		if(set_string(cconfs[OPT_CNAME], dirinfo->d_name))
			return -1;

		if(conf_load_clientconfdir(globalcs, cconfs))
		{
			logp("could not load config for client %s\n",
				dirinfo->d_name);
			return 0;
		}

		if(grouplist)
		{
			const char *dedup_group=
				get_string(cconfs[OPT_DEDUP_GROUP]);
			if(!dedup_group
			  || !in_group(grouplist, dedup_group))
				continue;
		}

		if(!(client_lockdir=get_string(cconfs[OPT_CLIENT_LOCKDIR])))
			client_lockdir=get_string(cconfs[OPT_DIRECTORY]);

		if(!(lockfilebase=prepend_s(client_lockdir, dirinfo->d_name))
		 || !(lockfile=prepend_s(lockfilebase, BEDUP_LOCKFILE_NAME)))
		{
			free_w(&lockfilebase);
			free_w(&lockfile);
			ret=-1;
			break;
		}
		free_w(&lockfilebase);

		if(!(lock=lock_alloc_and_init(lockfile)))
		{
			ret=-1;
			break;
		}
		lock_get(lock);
		free_w(&lockfile);

		if(lock->status!=GET_LOCK_GOT)
		{
			logp("Could not get %s\n", lock->path);
			continue;
		}
		logp("Got %s\n", lock->path);

		// Remember that we got that lock.
		lock_add_to_list(&locklist, lock);

		switch(process_dir(get_string(cconfs[OPT_DIRECTORY]),
			dirinfo->d_name,
			1 /* burp mode */, 0 /* level */))
		{
			case 0: ccount++;
			case 1: continue;
			default: ret=-1; break;
		}
		break;
	}
	closedir(dirp);

	locks_release_and_free(&locklist);

	confs_free(&cconfs);

	return ret;
}

static int process_from_conf(const char *configfile, char **groups)
{
	int ret=-1;
	struct conf **globalcs=NULL;
	struct strlist *grouplist=NULL;
	struct lock *globallock=NULL;

	signal(SIGABRT, &sighandler);
	signal(SIGTERM, &sighandler);
	signal(SIGINT, &sighandler);

	if(*groups)
	{
		char *tok=NULL;
		if((tok=strtok(*groups, ",\n")))
		{
			do
			{
				if(strlist_add(&grouplist, tok, 1))
				{
					log_out_of_memory(__func__);
					goto end;
				}
			} while((tok=strtok(NULL, ",\n")));
		}
		if(!grouplist)
		{
			logp("unable to read list of groups\n");
			goto end;
		}
	}

	// Read directories from config files, and get locks.
	if(!(globalcs=confs_alloc())
	  || confs_init(globalcs)
	  || conf_load_global_only(configfile, globalcs))
		goto end;

	if(get_e_burp_mode(globalcs[OPT_BURP_MODE])!=BURP_MODE_SERVER)
	{
		logp("%s is not a server config file\n", configfile);
		goto end;
	}
	logp("Dedup clients from %s\n",
		get_string(globalcs[OPT_CLIENTCONFDIR]));
	maxlinks=get_int(globalcs[OPT_MAX_HARDLINKS]);
	if(grouplist)
	{
		struct strlist *g=NULL;
		logp("in dedup groups:\n");
		for(g=grouplist; g; g=g->next)
			logp("%s\n", g->path);
	}
	else
	{
		char *lockpath=NULL;
		const char *opt_lockfile=confs_get_lockfile(globalcs);
		// Only get the global lock when doing a global run.
		// If you are doing individual groups, you are likely
		// to want to do many different dedup jobs and a
		// global lock would get in the way.
		if(!(lockpath=prepend(opt_lockfile, ".bedup"))
		  || !(globallock=lock_alloc_and_init(lockpath)))
			goto end;
		lock_get(globallock);
		if(globallock->status!=GET_LOCK_GOT)
		{
			logp("Could not get lock %s (%d)\n", lockpath,
				globallock->status);
			free_w(&lockpath);
			goto end;
		}
		logp("Got %s\n", lockpath);
	}
	ret=iterate_over_clients(globalcs, grouplist);
end:
	confs_free(&globalcs);
	lock_release(globallock);
	lock_free(&globallock);
	strlists_free(&grouplist);
	return ret;
}

static int process_from_command_line(int argc, char *argv[])
{
	int i;
	for(i=optind; i<argc; i++)
	{
		// Strip trailing slashes, for tidiness.
		if(argv[i][strlen(argv[i])-1]=='/')
			argv[i][strlen(argv[i])-1]='\0';
		if(process_dir("", argv[i],
			0 /* not burp mode */, 0 /* level */))
				return 1;
	}
	return  0;
}

static int usage(void)
{
	logfmt("\nUsage: %s [options]\n", prog);
	logfmt("\n");
	logfmt(" Options:\n");
	logfmt("  -c <path>                Path to config file (default: %s).\n", config_default_path());
	logfmt("  -g <list of group names> Only run on the directories of clients that\n");
	logfmt("                           are in one of the groups specified.\n");
	logfmt("                           The list is comma-separated. To put a client in a\n");
	logfmt("                           group, use the 'dedup_group' option in the client\n");
	logfmt("                           configuration file on the server.\n");
	logfmt("  -h|-?                    Print this text and exit.\n");
	logfmt("  -d                       Delete any duplicate files found.\n");
	logfmt("                           (non-%s mode only)\n", PACKAGE_TARNAME);
	logfmt("  -l                       Hard link any duplicate files found.\n");
	logfmt("  -m <number>              Maximum number of hard links to a single file.\n");
	logfmt("                           (non-%s mode only - in burp mode, use the\n", PACKAGE_TARNAME);
	logfmt("                           max_hardlinks option in the configuration file)\n");
	logfmt("                           The default is %d. On ext3, the maximum number\n", DEF_MAX_LINKS);
	logfmt("                           of links possible is 32000, but space is needed\n");
	logfmt("                           for the normal operation of %s.\n", PACKAGE_TARNAME);
	logfmt("  -n <list of directories> Non-%s mode. Deduplicate any (set of) directories.\n", PACKAGE_TARNAME);
	logfmt("  -v                       Print duplicate paths.\n");
	logfmt("  -V                       Print version and exit.\n");
	logfmt("\n");
	logfmt("By default, %s will read %s and deduplicate client storage\n", prog, config_default_path());
	logfmt("directories using special knowledge of the structure.\n");
	logfmt("\n");
	logfmt("With '-n', this knowledge is turned off and you have to specify the directories\n");
	logfmt("to deduplicate on the command line. Running with '-n' is therefore dangerous\n");
	logfmt("if you are deduplicating %s storage directories.\n\n", PACKAGE_TARNAME);
	return 1;
}

int run_bedup(int argc, char *argv[])
{
	int ret=0;
	int option=0;
	int nonburp=0;
	char *groups=NULL;
	int givenconfigfile=0;
	const char *configfile=NULL;

	configfile=config_default_path();
	snprintf(ext, sizeof(ext), ".bedup.%d", getpid());

	while((option=getopt(argc, argv, "c:dg:hlm:nvV?"))!=-1)
	{
		switch(option)
		{
			case 'c':
				configfile=optarg;
				givenconfigfile=1;
				break;
			case 'd':
				deletedups=1;
				break;
			case 'g':
				groups=optarg;
				break;
			case 'l':
				makelinks=1;
				break;
			case 'm':
				maxlinks=atoi(optarg);
				break;
			case 'n':
				nonburp=1;
				break;
			case 'V':
				logfmt("%s-%s\n", prog, PACKAGE_VERSION);
				return 0;
			case 'v':
				verbose=1;
				break;
			case 'h':
			case '?':
				return usage();
		}
	}

	if(nonburp && givenconfigfile)
	{
		logp("-n and -c options are mutually exclusive\n");
		return 1;
	}
	if(nonburp && groups)
	{
		logp("-n and -g options are mutually exclusive\n");
		return 1;
	}
	if(!nonburp && maxlinks!=DEF_MAX_LINKS)
	{
		logp("-m option is specified via the configuration file in %s mode (max_hardlinks=)\n", PACKAGE_TARNAME);
		return 1;
	}
	if(deletedups && makelinks)
	{
		logp("-d and -l options are mutually exclusive\n");
		return 1;
	}
	if(deletedups && !nonburp)
	{
		logp("-d option requires -n option\n");
		return 1;
	}

	if(optind>=argc)
	{
		if(nonburp)
		{
			logp("No directories found after options\n");
			return 1;
		}
	}
	else
	{
		if(!nonburp)
		{
			logp("Do not specify extra arguments.\n");
			return 1;
		}
	}

	if(maxlinks<2)
	{
		logp("The argument to -m needs to be greater than 1.\n");
		return 1;
	}

	if(nonburp)
	{
		// Read directories from command line.
		if(process_from_command_line(argc, argv))
			ret=1;
	}
	else
	{
		if(process_from_conf(configfile, &groups))
			ret=1;
	}

	if(!nonburp)
	{
		logp("%d client storages scanned\n", ccount);
	}
	logp("%" PRIu64 " duplicate %s found\n",
		count, count==1?"file":"files");
	logp("%" PRIu64 " bytes %s%s\n",
		savedbytes, (makelinks || deletedups)?"saved":"saveable",
			bytes_to_human(savedbytes));
	mystruct_delete_all();
	return ret;
}
