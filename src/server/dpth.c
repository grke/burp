#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <stdint.h>
#include <sys/types.h>
#include <dirent.h>

#include "../prepend.h"
#include "../handy.h"
#include "../log.h"
#include "../msg.h"
#include "dpth.h"
#include "hash.h"
#include "sbuf.h"

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

char *dpth_mk(struct dpth *dpth)
{
	static char path[32];
	snprintf(path, sizeof(path), "%04X/%04X/%04X/%04X",
		dpth->prim, dpth->seco, dpth->tert, dpth->sig);
	return path;
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
	}

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

struct dpth *dpth_alloc(const char *base_path)
{
        struct dpth *dpth;
        if((dpth=(struct dpth *)calloc(1, sizeof(struct dpth)))
	  && (dpth->base_path=strdup(base_path)))
		return dpth;
	log_out_of_memory(__FUNCTION__);
	dpth_free(dpth);
	return NULL;
}

int dpth_incr_sig(struct dpth *dpth)
{
	if(++dpth->sig<SIG_MAX) return 0;
	dpth->sig=0;
	return dpth_incr(dpth);
}

int dpth_init(struct dpth *dpth)
{
	int max;
	int ret=0;
	char *tmp=NULL;

	if(get_highest_entry(dpth->base_path, &max, NULL))
		goto error;
	if(max<0) max=0;
	dpth->prim=max;
	tmp=dpth_mk_prim(dpth);
	if(!(tmp=prepend_s(dpth->base_path, tmp, strlen(tmp))))
		goto error;

	if(get_highest_entry(tmp, &max, NULL))
		goto error;
	if(max<0) max=0;
	dpth->seco=max;
	free(tmp);
	tmp=dpth_mk_seco(dpth);
	if(!(tmp=prepend_s(dpth->base_path, tmp, strlen(tmp))))
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
	free(dpth);
	dpth=NULL;
}
