#include <stdio.h>
#include <string.h>
#include <sys/stat.h>
#include <dirent.h>
#include <errno.h>
#include <libgen.h>
#include <unistd.h>

#include <openssl/md5.h>

#include "log.h"
#include "uthash/uthash.h"

static int makelinks=0;
static char *prog=NULL;

static unsigned long long savedbytes=0;
static unsigned long long count=0;

typedef struct file file_t;

struct file
{
	char *path;
	dev_t dev;
	ino_t ino;
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

static size_t read_chunk(FILE *fp, char *buf, size_t need)
{
	size_t s=0;
	size_t got=0;
	while((s=fread(buf+got, 1, need, fp))>0)
	{
		need-=s;
		got+=s;
	}
	return got;
}

static int full_match(struct file *o, struct file *n, FILE **ofp, FILE **nfp)
{
	size_t ogot;
	size_t ngot;
	char obuf[4096];
	char nbuf[4096];
	char *op=NULL;
	char *np=NULL;

	if(!*ofp && !(*ofp=open_file(o))) return 0;
	if(!*nfp && !(*nfp=open_file(n))) return 0;

	fseek(*ofp, 0, SEEK_SET);
	fseek(*nfp, 0, SEEK_SET);

	while(1)
	{
		ogot=read_chunk(*ofp, obuf, sizeof(obuf));
		ngot=read_chunk(*nfp, nbuf, sizeof(nbuf));
		if(ogot<0 || ogot!=ngot) return 0;
		if(!ogot) break;
		for(op=obuf, np=nbuf; *op; op++, np++)
			if(*op!=*np) return 0;
	}

	return 1;
}

static int get_part_cksum(struct file *f, FILE **fp)
{
	MD5_CTX md5;
	int got=0;
	char buf[4096]="";
	unsigned char checksum[MD5_DIGEST_LENGTH+1];

	if(!*fp && !(*fp=open_file(f))) return 1;
	fseek(*fp, 0, SEEK_SET);

	if(!MD5_Init(&md5))
	{
		logp("MD5_Init() failed\n");
		return -1;
	}

	got=read_chunk(*fp, buf, sizeof(buf));

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

	return 0;
}

static int get_full_cksum(struct file *f, FILE **fp)
{
	size_t s=0;
	MD5_CTX md5;
	char buf[4096]="";
	unsigned char checksum[MD5_DIGEST_LENGTH+1];

	if(!*fp && !(*fp=open_file(f))) return -1;
	fseek(*fp, 0, SEEK_SET);

	if(!MD5_Init(&md5))
	{
		logp("MD5_Init() failed\n");
		return -1;
	}

	while((s=fread(buf, 1, 4096, *fp))>0)
	{
		if(!MD5_Update(&md5, buf, s))
		{
			logp("MD5_Update() failed\n");
			return -1;
		}
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
		logp("could not rename '%s' to '%s': %s\n",
			oldpath, newpath, strerror(errno));
		return -1;
	}
	return 0;
}

static int do_hardlink(struct file *o, struct file *n, const char *ext)
{
	char pid[16]="";
	char *tmppath=NULL;
	snprintf(pid, sizeof(pid), ".bedup.%d", getpid());
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

static int check_files(struct mystruct *find, struct file *newfile, struct stat *info, const char *ext)
{
	int found=0;
	FILE *nfp=NULL;
	FILE *ofp=NULL;
	struct file *f=NULL;

	//printf("  same size: %s, %s\n", find->files->path, newfile->path);

	for(f=find->files; f; f=f->next)
	{
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
		if(!newfile->part_cksum && get_part_cksum(newfile, &nfp))
		{
			// Error, pretend that it was found, so
			// that it will be ignored from now
			// onwards.
			found++;
			break;
		}
		if(!f->part_cksum && get_part_cksum(f, &ofp))
		{
			// Error, continue trying to
			// find matches elsewhere.
			if(ofp) { fclose(ofp); ofp=NULL; }
			continue;
		}
		if(newfile->part_cksum!=f->part_cksum)
		{
			if(ofp) { fclose(ofp); ofp=NULL; }
			continue;
		}
		//printf("%s, %s\n", find->files->path, newfile->path);
		//printf("part cksum matched\n");

		if(!newfile->full_cksum && get_full_cksum(newfile, &nfp))
		{
			// Error, pretend that it was found,
			// so that it will be ignored from
			// now onwards.
			found++;
			break;
		}
		if(!f->full_cksum && get_full_cksum(f, &ofp))
		{
			// Error, continue trying to
			// find matches elsewhere.
			if(ofp) { fclose(ofp); ofp=NULL; }
			continue;
		}
		if(newfile->full_cksum!=f->full_cksum)
		{
			if(ofp) { fclose(ofp); ofp=NULL; }
			continue;
		}

		//printf("full cksum matched\n");
		if(!full_match(newfile, f, &nfp, &ofp))
		{
			if(ofp) { fclose(ofp); ofp=NULL; }
			continue;
		}
		//printf("full match\n");
		//printf("%s, %s\n", find->files->path, newfile->path);

		found++;
		count++;

		// Now hardlink it.
		if(makelinks)
		{
			if(!do_hardlink(newfile, f, ext))
				savedbytes+=info->st_size;
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
		free(newfile->path);
		return 0;
	}

	if((add_file(find, newfile))) return -1;

	return 0;
}

static int process_dir(const char *oldpath, const char *newpath, const char *ext)
{
	DIR *dirp=NULL;
	char *path=NULL;
	struct stat info;
	struct dirent *dirinfo=NULL;
	struct file newfile;
	struct mystruct *find=NULL;

	if(!(path=prepend(oldpath, newpath, "/"))) return -1;

	if(!(dirp=opendir(path)))
	{
		logp("could not opendir '%s': %s\n", path, strerror(errno));
		return 0;
	}
	while((dirinfo=readdir(dirp)))
	{
		if(!strcmp(dirinfo->d_name, ".")
		  || !strcmp(dirinfo->d_name, ".."))
			continue;

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
			if(process_dir(path, dirinfo->d_name, ext))
			{
				closedir(dirp);
				free(path);
				free(newfile.path);
				return -1;
			}
			free(newfile.path);
			continue;
		}
		else if(!S_ISREG(info.st_mode))
		{
			free(newfile.path);
			continue;
		}

		newfile.dev=info.st_dev;
		newfile.ino=info.st_ino;
		newfile.full_cksum=0;
		newfile.part_cksum=0;
		newfile.next=NULL;

		//printf("%s\n", newfile.path);

		if((find=find_key(info.st_size)))
		{
			if(check_files(find, &newfile, &info, ext))
			{
				closedir(dirp);
				free(path);
				return -1;
			}
		}
		else
		{
			//printf("add: %s\n", newfile.path);
			if((add_key(info.st_size, &newfile)))
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

static int usage(void)
{
	fprintf(stderr, "%s: [-l] <list of directories>\n\n", prog);
	fprintf(stderr, "If you give '-l', duplicate files will be replaced with hard links.\n");
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
	char ext[16]="";
	prog=basename(argv[0]);
	init_log(prog);

	if(argc<2
	  || !strcmp(argv[1], "-h")
	  || !strcmp(argv[1], "-?"))
		return usage();

	if(!strcmp(argv[1], "-l"))
	{
		i++;
		makelinks=1;
	}

	snprintf(ext, sizeof(ext), ".bedup.%d", getpid());
	for(; i<argc; i++)
	{
		// Strip trailing slashes, for tidiness.
		if(argv[i][strlen(argv[i])-1]=='/')
			argv[i][strlen(argv[i])-1]='\0';
		if(process_dir("", argv[i], ext))
		{
			ret=1;
			break;
		}
	}
	logp("%llu duplicate %s found\n",
		count, count==1?"file":"files");
	logp("%llu bytes %s%s\n",
		savedbytes, makelinks?"saved":"saveable",
			bytes_to_human(savedbytes));
	return ret;
}
