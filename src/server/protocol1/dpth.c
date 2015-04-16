#include "../../burp.h"
#include "../../alloc.h"
#include "../../cmd.h"
#include "../../conf.h"
#include "../../log.h"
#include "../../prepend.h"
#include "dpth.h"

#include <dirent.h>

char *dpthl_mk(struct dpth *dpthl, struct conf **cconfs, enum cmd cmd)
{
	static char path[32];
	// File data.
	snprintf(path, sizeof(path), "%04X/%04X/%04X%s",
		dpthl->prim, dpthl->seco, dpthl->tert,
		// Because of the way EFS works, it cannot be compressed.
		(get_int(cconfs[OPT_COMPRESSION])
			&& cmd!=CMD_EFS_FILE)?".gz":"");
	return path;
}

static char *dpthl_mk_prim(struct dpth *dpthl)
{
	static char path[5];
	snprintf(path, sizeof(path), "%04X", dpthl->prim);
	return path;
}

static char *dpthl_mk_seco(struct dpth *dpthl)
{
	static char path[10];
	snprintf(path, sizeof(path), "%04X/%04X", dpthl->prim, dpthl->seco);
	return path;
}

static void get_highest_entry(const char *path, uint16_t *max)
{
	int ent=0;
	DIR *d=NULL;
	struct dirent *dp=NULL;

	*max=0;
	if(!(d=opendir(path))) return;
	while((dp=readdir(d)))
	{
		if(dp->d_ino==0
		  || !strcmp(dp->d_name, ".")
		  || !strcmp(dp->d_name, ".."))
			continue;
		ent=strtol(dp->d_name, NULL, 16);
		if(ent>*max) *max=ent;
	}
	closedir(d);
}

static int get_next_comp(const char *currentdata,
	const char *path, uint16_t *comp)
{
	int ret=-1;
	char *tmp=NULL;
	if(path)
		tmp=prepend_s(currentdata, path);
	else
		tmp=strdup_w(currentdata, __func__);
	if(!tmp) goto end;

	get_highest_entry(tmp, comp);
	ret=0;
end:
	free_w(&tmp);
	return ret;
}

int dpthl_init(struct dpth *dpthl, const char *basepath, struct conf **cconfs)
{
	int ret=0;
	dpthl->prim=0;
	dpthl->seco=0;
	dpthl->tert=0;

	if((ret=get_next_comp(basepath,
		NULL, &dpthl->prim))) goto end;

	if((ret=get_next_comp(basepath,
		dpthl_mk_prim(dpthl), &dpthl->seco))) goto end;

	if((ret=get_next_comp(basepath,
		dpthl_mk_seco(dpthl), &dpthl->tert))) goto end;

	// At this point, we have the latest data file. Increment to get the
	// next free one.
	ret=dpthl_incr(dpthl, cconfs);

end:
	switch(ret)
	{
		case -1: return -1;
		default: return 0;
	}
}

// Three levels with 65535 entries each gives
// 65535^3 = 281,462,092,005,375 data entries
// recommend a filesystem with lots of inodes?
// Hmm, but ext3 only allows 32000 subdirs, although that many files are OK.
int dpthl_incr(struct dpth *dpthl, struct conf **cconfs)
{
	int max_storage_subdirs=get_int(cconfs[OPT_MAX_STORAGE_SUBDIRS]);
	if(dpthl->tert++<0xFFFF) return 0;
	dpthl->tert=0;

	if(dpthl->seco++<max_storage_subdirs) return 0;
	dpthl->seco=0;

	if(dpthl->prim++<max_storage_subdirs) return 0;
	dpthl->prim=0;

	logp("No free data file entries out of the %d*%d*%d available!\n",
		0xFFFF, max_storage_subdirs, max_storage_subdirs);
	logp("Recommend moving the client storage directory aside and starting again.\n");
	return -1;
}

int dpthl_set_from_string(struct dpth *dpthl, const char *datapath)
{
	unsigned int a=0;
	unsigned int b=0;
	unsigned int c=0;

	if(!datapath
	  || *datapath=='t') // The path used the tree style structure.
		return 0;

	if((sscanf(datapath, "%04X/%04X/%04X", &a, &b, &c))!=3)
		return -1;

	// Only set it if it is a higher one.
	if(dpthl->prim > (int)a
	  || dpthl->seco > (int)b
	  || dpthl->tert > (int)c) return 0;

	dpthl->prim=a;
	dpthl->seco=b;
	dpthl->tert=c;
	return 0;
}
