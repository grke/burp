#include "burp.h"
#include "handy.h"
#include "prog.h"
#include "msg.h"
#include "asyncio.h"
#include "counter.h"
#include "dpth.h"
#include "find.h"

static void mk_dpth(struct dpth *dpth, struct config *cconf)
{
	// file data
	snprintf(dpth->path, sizeof(dpth->path), "%04X/%04X/%04X%s",
	  dpth->prim, dpth->seco, dpth->tert, cconf->compression?".gz":"");
}

static void mk_dpth_prim(struct dpth *dpth)
{
	snprintf(dpth->path, sizeof(dpth->path), "%04X", dpth->prim);
}

static void mk_dpth_seco(struct dpth *dpth)
{
	snprintf(dpth->path, sizeof(dpth->path), "%04X/%04X",
		dpth->prim, dpth->seco);
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

int init_dpth(struct dpth *dpth, const char *currentdata, struct config *cconf)
{
	char *tmp=NULL;
	//logp("in init_dpth\n");
	dpth->looped=0;
	dpth->prim=0;
	dpth->seco=0;
	dpth->tert=0;

	if((dpth->prim=get_highest_entry(currentdata))<0)
	{
		// Could not open directory. Set all zeros.
		dpth->prim=0;
		mk_dpth(dpth, cconf);
		return 0;
	}
	mk_dpth_prim(dpth);
	if(!(tmp=prepend_s(currentdata, dpth->path, strlen(dpth->path))))
	{
		log_and_send("out of memory");
		return -1;
	}
	if((dpth->seco=get_highest_entry(tmp))<0)
	{
		// Could not open directory. Set zero.
		dpth->seco=0;
		mk_dpth(dpth, cconf);
		free(tmp);
		return 0;
	}
	free(tmp);
	mk_dpth_seco(dpth);
	if(!(tmp=prepend_s(currentdata, dpth->path, strlen(dpth->path))))
	{
		log_and_send("out of memory");
		return -1;
	}
	if((dpth->tert=get_highest_entry(tmp))<0)
	{
		// Could not open directory. Set zero.
		dpth->tert=0;
		mk_dpth(dpth, cconf);
		free(tmp);
		return 0;
	}
	// At this point, we have the latest data file. Increment to get the
	// next free one.
	incr_dpth(dpth, cconf);

	//logp("init_dpth: %d/%d/%d\n", dpth->prim, dpth->seco, dpth->tert);
	//logp("init_dpth: %s\n", dpth->path);
	return 0;
}

// Three levels with 65535 entries each gives
// 65535^3 = 281,462,092,005,375 data entries
// recommend a filesystem with lots of inodes?
int incr_dpth(struct dpth *dpth, struct config *cconf)
{
	if(dpth->tert++>=0xFFFF)
	{
		dpth->tert=0;
		if(dpth->seco++>=0xFFFF)
		{
			dpth->seco=0;
			if(dpth->prim++>=0xFFFF)
			{
				dpth->prim=0;
				// Start again from zero, so make sure that
				// the initial open of a data file is in an
				// incrementing loop with O_CREAT|O_EXCL.
				if(++(dpth->looped)>1)
				{
					logp("could not find any free data file entries out of the 15000^3 available!\n");
					return -1;
				}
			}
		}
	}
	//printf("before incr_dpth: %s %04X/%04X/%04X\n", dpth->path, dpth->prim, dpth->seco, dpth->tert);
	mk_dpth(dpth, cconf);
	//printf("after incr_dpth: %s\n", dpth->path);
	return 0;
}

int set_dpth_from_string(struct dpth *dpth, const char *datapath, struct config *cconf)
{
	unsigned int a=0;
	unsigned int b=0;
	unsigned int c=0;
	if(!datapath) return 0;

	if((sscanf(datapath, "%04X/%04X/%04X", &a, &b, &c))!=3)
		return -1;

	/* only set it if it is a higher one */
	if(dpth->prim > (int)a
	  || dpth->seco > (int)b
	  || dpth->tert > (int)c) return 0;

	dpth->prim=a;
	dpth->seco=b;
	dpth->tert=c;
	mk_dpth(dpth, cconf);
	return 0;
}
