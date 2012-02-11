#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <dirent.h>
#include <errno.h>
#include <libgen.h>
#include <unistd.h>
#include <stdarg.h>
#include <signal.h>
#include <malloc.h>

#include <uthash.h>
#include <openssl/md5.h>

#include "config.h"
#include "version.h"
#include "log.h"
#include "conf.h"
#include "lock.h"
#include "strlist.h"

#define LOCKFILE_NAME		"lockfile"
#define BEDUP_LOCKFILE_NAME	"lockfile.bedup"

#define DEF_MAX_LINKS		10000

static int makelinks=0;
static char *prog=NULL;

static unsigned long long savedbytes=0;
static unsigned long long count=0;
static int ccount=0;

static struct strlist **locklist=NULL;
static int lockcount=0;

typedef struct file file_t;

struct file
{
	char *path;
	dev_t dev;
	ino_t ino;
	nlink_t nlink;
	unsigned long full_cksum;
	unsigned long part_cksum;
	file_t *next;
};

struct mystruct
{
	off_t st_size;
	file_t *files;
	UT_hash_handle hh;
};

struct mystruct *myfiles=NULL;

struct mystruct *find_key(off_t st_size)
{
	struct mystruct *s;

	HASH_FIND_INT(myfiles, &st_size, s);
	return s;
}

static int add_file(struct mystruct *s, struct file *f)
{
	struct file *newfile;
	if(!(newfile=(struct file *)malloc(sizeof(struct file))))
	{
		logp("out of memory\n");
		return -1;
	}
	memcpy(newfile, f, sizeof(struct file));
	newfile->next=s->files;
	s->files=newfile;
	return 0;
}

static int add_key(off_t st_size, struct file *f)
{
	struct mystruct *s;

	if(!(s=(struct mystruct *)malloc(sizeof(struct mystruct))))
	{
		logp("out of memory\n");
		return -1;
	}
	s->st_size = st_size;
	s->files=NULL;
	if(add_file(s, f)) return -1;
	HASH_ADD_INT(myfiles, st_size, s);
	return 0;
}

static char *prepend(const char *oldpath, const char *newpath, const char *sep)
{
	int len=0;
	char *path=NULL;
	len+=strlen(oldpath);
	len+=strlen(newpath);
	len+=2;
	if(!(path=(char *)malloc(len)))
	{
		logp("out of memory\n");
		return NULL;
	}
	snprintf(path, len, "%s%s%s", oldpath, *oldpath?sep:"", newpath);
	return path;
}

static FILE *open_file(struct file *f)
{
	FILE *fp=NULL;
	if(!(fp=fopen(f->path, "rb")))
		logp("Could not open %s\n", f->path);
	return fp;
}

#define FULL_CHUNK	4096

static int full_match(struct file *o, struct file *n, FILE **ofp, FILE **nfp)
{
	size_t ogot;
	size_t ngot;
	unsigned int i=0;
	static char obuf[FULL_CHUNK];
	static char nbuf[FULL_CHUNK];

	if(*ofp) fseek(*ofp, 0, SEEK_SET);
	else if(!(*ofp=open_file(o)))
	{
		if(o->path)
		{
			// Blank this entry so that it can be ignored from
			// now on.
			free(o->path);
			o->path=NULL;
		}
		return 0;
	}

	if(*nfp) fseek(*nfp, 0, SEEK_SET);
	else if(!(*nfp=open_file(n))) return 0;

	while(1)
	{
		if((ogot=fread(obuf, 1, FULL_CHUNK, *ofp))<0) return 0;
		ngot=fread(nbuf, 1, FULL_CHUNK, *nfp);
		if(ogot!=ngot) return 0;
		for(i=0; i<ogot; i++)
			if(obuf[i]!=nbuf[i]) return 0;
		if(ogot<FULL_CHUNK) break;
	}

	return 1;
}

#define PART_CHUNK	1024

static int get_part_cksum(struct file *f, FILE **fp)
{
	MD5_CTX md5;
	int got=0;
	static char buf[PART_CHUNK];
	unsigned char checksum[MD5_DIGEST_LENGTH+1];

	if(*fp) fseek(*fp, 0, SEEK_SET);
	else if(!(*fp=open_file(f)))
	{
		f->part_cksum=0;
		return 0;
	}

	if(!MD5_Init(&md5))
	{
		logp("MD5_Init() failed\n");
		return -1;
	}

	got=fread(buf, 1, PART_CHUNK, *fp);

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

static int get_full_cksum(struct file *f, FILE **fp)
{
	size_t s=0;
	MD5_CTX md5;
	static char buf[FULL_CHUNK];
	unsigned char checksum[MD5_DIGEST_LENGTH+1];

	if(*fp) fseek(*fp, 0, SEEK_SET);
	else if(!(*fp=open_file(f)))
	{
		f->full_cksum=0;
		return 0;
	}

	if(!MD5_Init(&md5))
	{
		logp("MD5_Init() failed\n");
		return -1;
	}

	while((s=fread(buf, 1, FULL_CHUNK, *fp))>0)
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

static int do_rename(const char *oldpath, const char *newpath)
{
	if(rename(oldpath, newpath))
	{
		logp("Could not rename '%s' to '%s': %s\n",
			oldpath, newpath, strerror(errno));
		return -1;
	}
	return 0;
}

/* Make it atomic by linking to a temporary file, then moving it into place. */
static int do_hardlink(struct file *o, struct file *n, const char *ext)
{
	char *tmppath=NULL;
	if(!(tmppath=prepend(o->path, ext, "")))
	{
		logp("out of memory\n");
		return -1;
	}
	if(link(n->path, tmppath))
	{
		logp("Could not hardlink %s to %s: %s\n", tmppath, n->path,
			strerror(errno));
		free(tmppath);
		return -1;
	}
	if(do_rename(tmppath, o->path))
	{
		free(tmppath);
		return -1;
	}
	free(tmppath);
	return 0;
}

static void reset_old_file(struct file *oldfile, struct file *newfile, struct stat *info)
{
	//printf("reset %s with %s %d\n", oldfile->path, newfile->path,
	//	info->st_nlink);
	oldfile->nlink=info->st_nlink;
	if(oldfile->path) free(oldfile->path);
	oldfile->path=newfile->path;
	newfile->path=NULL;
}

static int check_files(struct mystruct *find, struct file *newfile, struct stat *info, const char *ext, unsigned int maxlinks)
{
	int found=0;
	FILE *nfp=NULL;
	FILE *ofp=NULL;
	struct file *f=NULL;

	//printf("  same size: %s, %s\n", find->files->path, newfile->path);

	for(f=find->files; f; f=f->next)
	{
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
		if((!newfile->part_cksum && get_part_cksum(newfile, &nfp))
		  || (!f->part_cksum && get_part_cksum(f, &ofp)))
		{
			// Some error with md5sums Give up.
			return -1;
		}
		if(newfile->part_cksum!=f->part_cksum)
		{
			if(ofp) { fclose(ofp); ofp=NULL; }
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
			if(ofp) { fclose(ofp); ofp=NULL; }
			continue;
		}

		//printf("  full cksum matched\n");
		if(!full_match(newfile, f, &nfp, &ofp))
		{
			if(ofp) { fclose(ofp); ofp=NULL; }
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

		// Now hardlink it.
		if(makelinks)
		{
			if(!do_hardlink(newfile, f, ext))
			{
				f->nlink++;
				// Only count bytes as saved if we removed the
				// last link.
				if(newfile->nlink==1)
					savedbytes+=info->st_size;
			}
			else
			{
				// On error, replace the memory of the old file
				// with the one that we just found. It might
				// work better when someone later tries to
				// link to the new one instead of the old one.
				reset_old_file(f, newfile, info);
				count--;
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
	if(nfp) { fclose(nfp); nfp=NULL; }
	if(ofp) { fclose(ofp); ofp=NULL; }

	if(found)
	{
		if(newfile->path) free(newfile->path);
		return 0;
	}

	if(add_file(find, newfile)) return -1;

	return 0;
}

static int get_link(const char *basedir, const char *lnk, char real[], size_t r)
{
	int len=0;
	char *tmp=NULL;
	if(!(tmp=prepend(basedir, lnk, "/")))
	{
		logp("out of memory");
		return -1;
	}
	if((len=readlink(tmp, real, r-1))<0) len=0;
	real[len]='\0';
	free(tmp);
	// Strip any trailing slash.
	if(real[strlen(real)-1]=='/') real[strlen(real)-1]='\0';
	return 0;
}


static int process_dir(const char *oldpath, const char *newpath, const char *ext, unsigned int maxlinks, int burp_mode, int level)
{
	DIR *dirp=NULL;
	char *path=NULL;
	struct stat info;
	struct dirent *dirinfo=NULL;
	struct file newfile;
	struct mystruct *find=NULL;
	static char working[256]="";
	static char finishing[256]="";

	if(!(path=prepend(oldpath, newpath, "/"))) return -1;

	if(burp_mode && level==0)
	{
		if(get_link(path, "working", working, sizeof(working))
		  || get_link(path, "finishing", finishing, sizeof(finishing)))
		{
			free(path);
			return -1;
		}
	}

	if(!(dirp=opendir(path)))
	{
		logp("Could not opendir '%s': %s\n", path, strerror(errno));
		return 0;
	}
	while((dirinfo=readdir(dirp)))
	{
		if(!strcmp(dirinfo->d_name, ".")
		  || !strcmp(dirinfo->d_name, ".."))
			continue;

		//printf("try %s\n", dirinfo->d_name);

		if(burp_mode)
		{
		  if(level==0)
		  {
			/* Be careful not to try to dedup the lockfiles.
			   The lock actually gets lost if you open one to do a
			   checksum
			   and then close it. This caused me major headaches to
			   figure out. */
			if(!strcmp(dirinfo->d_name, LOCKFILE_NAME)
			  || !strcmp(dirinfo->d_name, BEDUP_LOCKFILE_NAME))
				continue;

			/* Skip places where backups are going on. */
			if(!strcmp(dirinfo->d_name, working)
			  || !strcmp(dirinfo->d_name, finishing))
				continue;

			if(!strcmp(dirinfo->d_name, "deleteme"))
				continue;
		  }
		  else if(level==1)
		  {
			/* Do not dedup stuff that might be appended to later.
			*/
			if(!strncmp(dirinfo->d_name, "log",
				strlen("log"))
			  || !strncmp(dirinfo->d_name, "verifylog",
				strlen("verifylog"))
			  || !strncmp(dirinfo->d_name, "restorelog",
				strlen("restorelog")))
					continue;
		  }
		}

		if(!(newfile.path=prepend(path, dirinfo->d_name, "/")))
		{
			closedir(dirp);
			free(path);
			return -1;
		}

		if(lstat(newfile.path, &info))
		{
			free(newfile.path);
			continue;
		}

		if(S_ISDIR(info.st_mode))
		{
			if(process_dir(path, dirinfo->d_name, ext, maxlinks,					burp_mode, level+1))
			{
				closedir(dirp);
				free(path);
				free(newfile.path);
				return -1;
			}
			free(newfile.path);
			continue;
		}
		else if(!S_ISREG(info.st_mode)
		  || !info.st_size) // ignore zero-length files
		{
			free(newfile.path);
			continue;
		}

		newfile.dev=info.st_dev;
		newfile.ino=info.st_ino;
		newfile.nlink=info.st_nlink;
		newfile.full_cksum=0;
		newfile.part_cksum=0;
		newfile.next=NULL;

		//printf("%s\n", newfile.path);

		if((find=find_key(info.st_size)))
		{
			if(check_files(find, &newfile, &info, ext, maxlinks))
			{
				closedir(dirp);
				free(path);
				return -1;
			}
		}
		else
		{
			//printf("add: %s\n", newfile.path);
			if(add_key(info.st_size, &newfile))
			{
				closedir(dirp);
				free(path);
				return -1;
			}
			continue;
		}
	}
	closedir(dirp);
	free(path);
	return 0;
}

static int looks_like_vim_tmpfile(const char *filename)
{
	const char *cp=NULL;
	// vim tmpfiles look like ".filename.swp".
	if(filename[0]=='.'
	  && (cp=strrchr(filename, '.'))
	  && !strcmp(cp, ".swp"))
		return 1;
	return 0;
}

static int in_group(const char *clientconfdir, const char *client, strlist_t **grouplist, int gcount, struct config *conf)
{
	int i=0;
	char *ccfile=NULL;
	struct config cconf;

	if(!(ccfile=prepend(clientconfdir, client, "/"))) return -1;
	init_config(&cconf);
	if(set_client_global_config(conf, &cconf)
	  || load_config(ccfile, &cconf, 0))
	{
		logp("could not load config for client %s\n", client);
		free(ccfile);
		return 0;
	}
	free(ccfile);

	if(!cconf.dedup_group) return 0;

	for(i=0; i<gcount; i++)
		if(!strcmp(grouplist[i]->path, cconf.dedup_group))
			return 1;
	return 0;
}

static void remove_locks(void)
{
	int i=0;
	// Remove locks.
	for(i=0; i<lockcount; i++)
		unlink(locklist[i]->path);

	strlists_free(locklist, lockcount);
	lockcount=0;
}

static void sighandler(int signum)
{
	remove_locks();
	exit(1);
}

static int iterate_over_clients(struct config *conf, strlist_t **grouplist, int gcount, const char *ext, unsigned int maxlinks)
{
	int ret=0;
	DIR *dirp=NULL;
	struct dirent *dirinfo=NULL;

	signal(SIGABRT, &sighandler);
	signal(SIGTERM, &sighandler);
	signal(SIGINT, &sighandler);

	if(!(dirp=opendir(conf->clientconfdir)))
	{
		logp("Could not opendir '%s': %s\n",
			conf->clientconfdir, strerror(errno));
		return 0;
	}
	while((dirinfo=readdir(dirp)))
	{
		char *lockfile=NULL;
		char *lockfilebase=NULL;
		if(!strcmp(dirinfo->d_name, ".")
		  || !strcmp(dirinfo->d_name, "..")
		  || looks_like_vim_tmpfile(dirinfo->d_name))
			continue;

		if(gcount)
		{
			int ig=0;
			if((ig=in_group(conf->clientconfdir,
				dirinfo->d_name, grouplist, gcount, conf))<0)
			{
				ret=-1;
				break;
			}
			if(!ig) continue;
		}

		if(!(lockfilebase=prepend(conf->client_lockdir,
			dirinfo->d_name, "/"))
		 || !(lockfile=prepend(lockfilebase,
			BEDUP_LOCKFILE_NAME, "/")))
		{
			if(lockfilebase) free(lockfilebase);
			if(lockfile) free(lockfile);
			ret=-1;
			break;
		}
		free(lockfilebase);

		if(get_lock(lockfile))
		{
			logp("Could not get %s\n", lockfile);
			free(lockfile);
			continue;
		}

		// Remember that we got that lock.
		if(strlist_add(&locklist, &lockcount, lockfile, 1))
		{
			free(lockfile);
			lockcount=0;
			break;
		}

		logp("Got %s\n", lockfile);

		if(process_dir(conf->directory, dirinfo->d_name,
			ext, maxlinks, 1 /* burp mode */, 0 /* level */))
		{
			ret=-1;
			break;
		}

		ccount++;
	}
	closedir(dirp);

	remove_locks();

	return ret;
}

static char *get_config_path(void)
{
        static char path[256]="";
        snprintf(path, sizeof(path), "%s", SYSCONFDIR "/burp.conf");
        return path;
}

static int usage(void)
{
	printf("\n%s: [options]\n", prog);
	printf("\n");
	printf(" Options:\n");
	printf("  -c <path>                Path to config file (default: %s).\n", get_config_path());
	printf("  -g <list of group names> Only run on the directories of clients that\n");
	printf("                           are in one of the groups specified.\n");
	printf("                           The list is comma-separated. To put a client in a\n");
	printf("                           group, use the 'dedup_group' option in the client\n");
	printf("                           configuration file on the server.\n");
	printf("  -h|-?                    Print this text and exit.\n");
	printf("  -l                       Hard link any duplicate files found.\n");
	printf("  -m <number>              Maximum number of hard links to a single file.\n");
	printf("                           (non-burp mode only - in burp mode, use the\n");
	printf("                           max_hardlinks option in the configuration file)\n");
	printf("                           The default is %d. On ext3, the maximum number\n", DEF_MAX_LINKS);
	printf("                           of links possible is 32000, but space is needed\n");
	printf("                           for the normal operation of burp.\n");
	printf("  -n <list of directories> Non-burp mode. Deduplicate any (set of) directories.\n");
	printf("  -v                       Print version and exit.\n");
	printf("\n");
	printf("By default, %s will read %s and deduplicate client storage\n", prog, get_config_path());
	printf("directories using special knowledge of the structure.\n");
	printf("\n");
	printf("With '-n', this knowledge is turned off and you have to specify the directories\n");
	printf("to deduplicate on the command line. Running with '-n' is therefore dangerous\n");
	printf("if you are deduplicating burp storage directories.\n\n");
	return 1;
}

static const char *bytes_to_human(unsigned long long counter)
{
	static char ret[32]="";
	float div=(float)counter;
	char units[3]="";

	if(div<1024) return "";

	if((div/=1024)<1024)
		snprintf(units, sizeof(units), "KB");
	else if((div/=1024)<1024)
		snprintf(units, sizeof(units), "MB");
	else if((div/=1024)<1024)
		snprintf(units, sizeof(units), "GB");
	else if((div/=1024)<1024)
		snprintf(units, sizeof(units), "TB");
	else if((div/=1024)<1024)
		snprintf(units, sizeof(units), "EB");
	else
	{
		div/=1024;
		snprintf(units, sizeof(units), "PB");
	}
	snprintf(ret, sizeof(ret), " (%.2f %s)", div, units);
	//strcat(ret, units);
	//strcat(ret, ")");
	return ret;
}

int main(int argc, char *argv[])
{
	int i=1;
	int ret=0;
	int option=0;
	int nonburp=0;
	unsigned int maxlinks=DEF_MAX_LINKS;
	char *groups=NULL;
	char ext[16]="";
	int givenconfigfile=0;
	prog=basename(argv[0]);
	init_log(prog);
	const char *configfile=NULL;

	configfile=get_config_path();
	snprintf(ext, sizeof(ext), ".bedup.%d", getpid());

	while((option=getopt(argc, argv, "c:g:hlmnv?"))!=-1)
	{
		switch(option)
		{
			case 'c':
				configfile=optarg;
				givenconfigfile=1;
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
			case 'v':
				printf("%s-%s\n", prog, VERSION);
				return 0;
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
		logp("-m option is specified via the configuration file in burp mode (max_hardlinks=)\n");
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
		for(i=optind; i<argc; i++)
		{
			// Strip trailing slashes, for tidiness.
			if(argv[i][strlen(argv[i])-1]=='/')
				argv[i][strlen(argv[i])-1]='\0';
			if(process_dir("", argv[i], ext, maxlinks,
				0 /* not burp mode */, 0 /* level */))
			{
				ret=1;
				break;
			}
		}
	}
	else
	{
		int gcount=0;
		struct config conf;
		char *globallock=NULL;
		struct strlist **grouplist=NULL;

		if(groups)
		{
			char *tok=NULL;
			if((tok=strtok(groups, ",\n")))
			{
				do
				{
					if(strlist_add(&grouplist, &gcount,
						tok, 1))
					{
						logp("out of memory\n");
						return -1;
					}
				} while((tok=strtok(NULL, ",\n")));
			}
			if(!gcount)
			{
				logp("unable to read list of groups\n");
				return -1;
			}
		}

		// Read directories from config files, and get locks.
		init_config(&conf);
		if(load_config(configfile, &conf, 1)) return 1;
		if(conf.mode!=MODE_SERVER)
		{
			logp("%s is not a server config file\n", configfile);
			free_config(&conf);
			return 1;
		}
		logp("Dedup clients from %s\n", conf.clientconfdir);
		maxlinks=conf.max_hardlinks;
		if(gcount)
		{
			logp("in dedup groups:\n");
			for(i=0; i<gcount; i++)
				logp("%s\n", grouplist[i]->path);
		}
		else
		{
			// Only get the global lock when doing a global run.
			// If you are doing individual groups, you are likely
			// to want to do many different dedup jobs and a
			// global lock would get in the way.
			if(!(globallock=prepend(conf.lockfile, ".bedup", "")))
				return 1;
			if(get_lock(globallock))
			{
				logp("Could not get %s\n", globallock);
				return 1;
			}
			logp("Got %s\n", globallock);
		}
		ret=iterate_over_clients(&conf, grouplist, gcount,
			ext, maxlinks);
		free_config(&conf);

		if(globallock)
		{
			unlink(globallock);
			free(globallock);
		}
	}

	if(!nonburp)
	{
		logp("%d client storages scanned\n", ccount);
	}
	logp("%llu duplicate %s found\n",
		count, count==1?"file":"files");
	logp("%llu bytes %s%s\n",
		savedbytes, makelinks?"saved":"saveable",
			bytes_to_human(savedbytes));
	return ret;
}
