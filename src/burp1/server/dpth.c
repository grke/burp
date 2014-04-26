#include "include.h"
#include "../burp2/server/sdirs.h"

#include <dirent.h>

void mk_dpthl(struct dpthl *dpthl, struct conf *cconf, char cmd)
{
	// file data
	snprintf(dpthl->path, sizeof(dpthl->path), "%04X/%04X/%04X%s",
	  dpthl->prim, dpthl->seco, dpthl->tert,
	  /* Because of the way EFS works, it cannot be compressed. */
	  (cconf->compression && cmd!=CMD_EFS_FILE)?".gz":"");
}

static void mk_dpthl_prim(struct dpthl *dpthl)
{
	snprintf(dpthl->path, sizeof(dpthl->path), "%04X", dpthl->prim);
}

static void mk_dpthl_seco(struct dpthl *dpthl)
{
	snprintf(dpthl->path, sizeof(dpthl->path), "%04X/%04X",
		dpthl->prim, dpthl->seco);
}

static int get_highest_entry(const char *path)
{
	int ent=0;
	int max=0;
	DIR *d=NULL;
	struct dirent *dp=NULL;

	if(!(d=opendir(path))) return -1;
	while((dp=readdir(d)))
	{
		if(dp->d_ino==0
		  || !strcmp(dp->d_name, ".")
		  || !strcmp(dp->d_name, ".."))
		continue;
		ent=strtol(dp->d_name, NULL, 16);
		if(ent>max) max=ent;
	}
	closedir(d);
	return max;
}

int init_dpthl(struct dpthl *dpthl, struct async *as,
	struct sdirs *sdirs, struct conf *cconf)
{
	char *tmp=NULL;
	//logp("in init_dpthl\n");
	dpthl->looped=0;
	dpthl->prim=0;
	dpthl->seco=0;
	dpthl->tert=0;

	if((dpthl->prim=get_highest_entry(sdirs->currentdata))<0)
	{
		// Could not open directory. Set all zeros.
		dpthl->prim=0;
//		mk_dpthl(dpthl, cconf);
		return 0;
	}
	mk_dpthl_prim(dpthl);
	if(!(tmp=prepend_s(sdirs->currentdata, dpthl->path)))
	{
		log_and_send_oom(as, __func__);
		return -1;
	}
	if((dpthl->seco=get_highest_entry(tmp))<0)
	{
		// Could not open directory. Set zero.
		dpthl->seco=0;
//		mk_dpthl(dpthl, cconf);
		free(tmp);
		return 0;
	}
	free(tmp);
	mk_dpthl_seco(dpthl);
	if(!(tmp=prepend_s(sdirs->currentdata, dpthl->path)))
	{
		log_and_send_oom(as, __func__);
		return -1;
	}
	if((dpthl->tert=get_highest_entry(tmp))<0)
	{
		// Could not open directory. Set zero.
		dpthl->tert=0;
//		mk_dpthl(dpthl, cconf);
		free(tmp);
		return 0;
	}
	// At this point, we have the latest data file. Increment to get the
	// next free one.
	if(incr_dpthl(dpthl, cconf)) return -1;

	//logp("init_dpthl: %d/%d/%d\n", dpthl->prim, dpthl->seco, dpthl->tert);
	//logp("init_dpthl: %s\n", dpthl->path);
	return 0;
}

// Three levels with 65535 entries each gives
// 65535^3 = 281,462,092,005,375 data entries
// recommend a filesystem with lots of inodes?
// Hmm, but ext3 only allows 32000 subdirs, although that many files are OK.
int incr_dpthl(struct dpthl *dpthl, struct conf *cconf)
{
	if(dpthl->tert++>=0xFFFF)
	{
		dpthl->tert=0;
		if(dpthl->seco++>=cconf->max_storage_subdirs)
		{
			dpthl->seco=0;
			if(dpthl->prim++>=cconf->max_storage_subdirs)
			{
				dpthl->prim=0;
				// Start again from zero, so make sure that
				// the initial open of a data file is in an
				// incrementing loop with O_CREAT|O_EXCL.
				if(++(dpthl->looped)>1)
				{
					logp("Could not find any free data file entries out of the 15000*%d*%d available!\n", cconf->max_storage_subdirs, cconf->max_storage_subdirs);
					logp("Recommend moving the client storage directory aside and starting again.\n");
					return -1;
				}
			}
		}
	}
	//printf("before incr_dpthl: %s %04X/%04X/%04X\n", dpthl->path, dpthl->prim, dpthl->seco, dpthl->tert);
//	mk_dpthl(dpthl, cconf);
	//printf("after incr_dpthl: %s\n", dpthl->path);
	return 0;
}

int set_dpthl_from_string(struct dpthl *dpthl, const char *datapath, struct conf *cconf)
{
	unsigned int a=0;
	unsigned int b=0;
	unsigned int c=0;

	if(!datapath
	  || *datapath=='t') // The path used the tree style structure.
		return 0;

	if((sscanf(datapath, "%04X/%04X/%04X", &a, &b, &c))!=3)
		return -1;

	/* only set it if it is a higher one */
	if(dpthl->prim > (int)a
	  || dpthl->seco > (int)b
	  || dpthl->tert > (int)c) return 0;

	dpthl->prim=a;
	dpthl->seco=b;
	dpthl->tert=c;
//	mk_dpthl(dpthl, cconf);
	return 0;
}
