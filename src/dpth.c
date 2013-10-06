#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <stdint.h>
#include <sys/types.h>
#include <dirent.h>

#include "dpth.h"
#include "prepend.h"
#include "handy.h"
#include "hash.h"
#include "log.h"
#include "msg.h"

#define MAX_STORAGE_SUBDIRS	30000

static char *dpth_mk_prim(struct dpth *dpth)
{
	static char path[8];
	snprintf(path, sizeof(path), "%04X", dpth->prim);
	return path;
}

static char *dpth_mk_seco(struct dpth *dpth)
{
	static char path[16];
	snprintf(path, sizeof(path), "%04X/%04X", dpth->prim, dpth->seco);
	return path;
}

static char *dpth_mk_tert(struct dpth *dpth)
{
	static char path[24];
	snprintf(path, sizeof(path), "%04X/%04X/%04X",
		dpth->prim, dpth->seco, dpth->tert);
	return path;
}

char *dpth_mk(struct dpth *dpth)
{
	static char path[32];
	snprintf(path, sizeof(path), "%04X/%04X/%04X/%04X",
		dpth->prim, dpth->seco, dpth->tert, dpth->sig);
	return path;
}

/*
static int process_sig(char cmd, const char *buf, unsigned int s, struct dpth *dpth, void *ignored)
{
        static uint64_t weakint;
        static struct weak_entry *weak_entry;
        static char weak[16+1];
        static char strong[32+1];

        if(split_sig(buf, s, weak, strong)) return -1;

        weakint=strtoull(weak, 0, 16);

	weak_entry=find_weak_entry(weakint);

	// Add to hash table.
	if(!weak_entry && !(weak_entry=add_weak_entry(weakint)))
		return -1;
	if(!find_strong_entry(weak_entry, strong))
	{
		if(!(weak_entry->strong=add_strong_entry(weak_entry,
			strong, dpth))) return -1;
	}
	dpth->sig++;

	return 0;
}
*/

int split_stream(FILE *ifp, struct dpth *dpth, void *flag,
  int (*process_dat)(char, const char *, unsigned int, struct dpth *, void *),
  int (*process_man)(char, const char *, unsigned int, struct dpth *, void *),
  int (*process_sig)(char, const char *, unsigned int, struct dpth *, void *))
{
        int ret=0;
        char cmd='\0';
        size_t bytes;
        char buf[1048576];
        unsigned int s;

        while((bytes=fread(buf, 1, 5, ifp)))
        {
                if(bytes!=5)
                {
                        logp("Short read: %d wanted: %d\n", (int)bytes, 5);
                        goto end;
                }
                if((sscanf(buf, "%c%04X", &cmd, &s))!=2)
                {
                        logp("sscanf failed: %s\n", buf);
                        goto end;
                }

                if((bytes=fread(buf, 1, s, ifp))!=s)
                {
                        logp("Short read: %d wanted: %d\n", (int)bytes, (int)s);
                        goto error;
                }

                if(cmd=='a')
                {
                        if(process_dat && process_dat(cmd, buf, s, dpth, &flag))
                                goto error;
                }
                else if(cmd=='f')
                {
                        if(process_man && process_man(cmd, buf, s, dpth, &flag))
                                goto error;
                }
                else if(cmd=='S')
                {
			s--;
			buf[s]=0;
                        if(process_sig && process_sig(cmd, buf, s, dpth, &flag))
                                goto error;
                }
                else
                {
                        logp("unknown cmd: %c\n", cmd);
                        goto error;
                }
        }

        goto end;
error:
        ret=-1;
end:
        return ret;
}

// Returns 0 on OK, -1 on error. *max gets set to the next entry.
static int get_highest_entry(const char *path, int *max, struct dpth *dpth)
{
	int ent=0;
	int ret=0;
	DIR *d=NULL;
	char *tmp=NULL;
	struct dirent *dp=NULL;
	FILE *ifp=NULL;

	*max=-1;
	if(!(d=opendir(path))) goto end;
	while((dp=readdir(d)))
	{
		if(dp->d_ino==0
		  || !strcmp(dp->d_name, ".")
		  || !strcmp(dp->d_name, ".."))
			continue;
		ent=strtol(dp->d_name, NULL, 16);
		if(ent>*max) *max=ent;
/*
		if(dpth)
		{
			dpth->tert=ent;
			dpth->sig=0;
			if(!(tmp=prepend_s(path,
				dp->d_name, strlen(dp->d_name))))
					goto error;
			if(!(ifp=open_file(tmp, "rb")))
				goto error;
fprintf(stderr, "LOAD: %s\n", tmp);
			if(split_stream(ifp, dpth, NULL,
				NULL, NULL, process_sig))
					goto error;
			free(tmp); tmp=NULL;
			fclose(ifp); ifp=NULL;
		}
*/
	}

	goto end;
//error:
//	ret=-1;
end:
	if(d) closedir(d);
	if(ifp) fclose(ifp);
	if(tmp) free(tmp);
	return ret;
}

static int get_next_entry(const char *path, int *max, struct dpth *dpth)
{
	if(get_highest_entry(path, max, dpth)) return -1;
	(*max)++;
	return 0;
}

// Three levels with 65535 entries each gives
// 65535^3 = 281,462,092,005,375 data entries
// recommend a filesystem with lots of inodes?
// Hmm, but ext3 only allows 32000 subdirs, although that many files are OK.
static int dpth_incr(struct dpth *dpth)
{
	if(dpth->tert++<0xFFFF) return 0;
	dpth->tert=0;
	if(dpth->seco++<MAX_STORAGE_SUBDIRS) return 0;
	dpth->seco=0;
	if(dpth->prim++<MAX_STORAGE_SUBDIRS) return 0;
	dpth->prim=0;
	logp("Could not find any free data file entries out of the 15000*%d*%d available!\n", MAX_STORAGE_SUBDIRS, MAX_STORAGE_SUBDIRS);
	logp("Recommend moving the client storage directory aside and starting again.\n");
	return -1;
}

static char *dpth_get_path_dat(struct dpth *dpth)
{
	char *path=dpth_mk_tert(dpth);
	return prepend_s(dpth->base_path_dat, path, strlen(path));
}

static char *dpth_get_path_sig(struct dpth *dpth)
{
	char *path=dpth_mk_tert(dpth);
	return prepend_s(dpth->base_path_sig, path, strlen(path));
}

struct dpth *dpth_alloc(const char *base_path)
{
        struct dpth *dpth;
        if(!(dpth=(struct dpth *)calloc(1, sizeof(struct dpth)))
	  || !(dpth->base_path=strdup(base_path)))
	{
		log_out_of_memory(__FUNCTION__);
                goto error;
	}
	if((dpth->base_path_dat=prepend_s(base_path, "dat", strlen("dat")))
	  && (dpth->base_path_sig=prepend_s(base_path, "sig", strlen("sig"))))
		goto end;
error:
	dpth_free(dpth);
	dpth=NULL;
end:
	return dpth;
}

// The files get closed and path_dat/path_sig get freed in backup_server.c
// now, but it is nasty.
static struct dpth_fp *dpth_fp_alloc(struct dpth *dpth)
{
	struct dpth_fp *dpth_fp;
        if(!(dpth_fp=(struct dpth_fp *)calloc(1, sizeof(struct dpth_fp)))
	  || !(dpth_fp->path_dat=dpth_get_path_dat(dpth))
	  || !(dpth_fp->path_sig=dpth_get_path_sig(dpth)))
	{
		log_out_of_memory(__FUNCTION__);
		return NULL;
	}
	return dpth_fp;
}

static struct dpth_fp *gdpth_fp=NULL;

struct dpth_fp *get_dpth_fp(struct dpth *dpth)
{
	if(!gdpth_fp) gdpth_fp=dpth_fp_alloc(dpth);
	return gdpth_fp;
}

struct dpth_fp *dpth_incr_sig(struct dpth *dpth)
{
	if(++(dpth->sig)<SIG_MAX)
	{
		return gdpth_fp;
	}
	dpth->sig=0;

	if(dpth_incr(dpth)) return NULL;

	gdpth_fp=dpth_fp_alloc(dpth);
	return gdpth_fp;
}

int dpth_init(struct dpth *dpth)
{
	int max;
	int ret=0;
	char *tmp=NULL;

	if(get_highest_entry(dpth->base_path_dat, &max, NULL))
		goto error;
	if(max<0) max=0;
	dpth->prim=max;
	tmp=dpth_mk_prim(dpth);
	if(!(tmp=prepend_s(dpth->base_path_dat, tmp, strlen(tmp))))
		goto error;

	if(get_highest_entry(tmp, &max, NULL))
		goto error;
	if(max<0) max=0;
	dpth->seco=max;
	free(tmp);
	tmp=dpth_mk_seco(dpth);
	if(!(tmp=prepend_s(dpth->base_path_dat, tmp, strlen(tmp))))
		goto error;

	if(get_next_entry(tmp, &max, dpth))
		goto error;
	if(max<0) max=0;
	dpth->tert=max;

	dpth->sig=0;

	goto end;
error:
	ret=-1;
end:
	if(tmp) free(tmp);
	return ret;
}

void dpth_free(struct dpth *dpth)
{
	if(!dpth) return;
	if(dpth->base_path) free(dpth->base_path);
	if(dpth->base_path_dat) free(dpth->base_path_dat);
	if(dpth->base_path_sig) free(dpth->base_path_sig);
	free(dpth);
	dpth=NULL;
}

int dpth_fp_close(struct dpth_fp *dpth_fp)
{
	if(dpth_fp)
	{
		if(close_fp(&(dpth_fp->sfp))) return -1;
		if(close_fp(&(dpth_fp->dfp))) return -1;
		if(dpth_fp->path_dat) free(dpth_fp->path_dat);
		if(dpth_fp->path_sig) free(dpth_fp->path_sig);
		free(dpth_fp);
	}
	return 0;
}

int dpth_fp_maybe_close(struct dpth_fp *dpth_fp)
{
	if(dpth_fp && ++(dpth_fp->count)>=SIG_MAX)
		return dpth_fp_close(dpth_fp);
	return 0;
}
