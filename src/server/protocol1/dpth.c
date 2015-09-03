#include "../../burp.h"
#include "../../alloc.h"
#include "../../cmd.h"
#include "../../conf.h"
#include "../../log.h"
#include "../../prepend.h"
#include "dpth.h"

char *dpth_protocol1_mk(struct dpth *dpth, int compression, enum cmd cmd)
{
	static char path[32];
	// File data.
	snprintf(path, sizeof(path), "%04X/%04X/%04X%s",
		dpth->comp[0], dpth->comp[1], dpth->comp[2],
		// Because of the way EFS works, it cannot be compressed.
		(compression && cmd!=CMD_EFS_FILE)?".gz":"");
	return path;
}

static char *dpth_mk_prim(struct dpth *dpth)
{
	static char path[5];
	snprintf(path, sizeof(path), "%04X", dpth->comp[0]);
	return path;
}

static char *dpth_mk_seco(struct dpth *dpth)
{
	static char path[10];
	snprintf(path, sizeof(path), "%04X/%04X", dpth->comp[0], dpth->comp[1]);
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
		if(!dp->d_ino
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

int dpth_protocol1_init(struct dpth *dpth, const char *basepath,
	int max_storage_subdirs)
{
	int ret=0;
	dpth->savepath=0;
	dpth->max_storage_subdirs=max_storage_subdirs;

	if((ret=get_next_comp(basepath,
		NULL, &dpth->comp[0]))) goto end;

	if((ret=get_next_comp(basepath,
		dpth_mk_prim(dpth), &dpth->comp[1]))) goto end;

	if((ret=get_next_comp(basepath,
		dpth_mk_seco(dpth), &dpth->comp[2]))) goto end;

	// At this point, we have the latest data file. Increment to get the
	// next free one.
	ret=dpth_incr(dpth);

end:
	switch(ret)
	{
		case -1: return -1;
		default: return 0;
	}
}

int dpth_protocol1_set_from_string(struct dpth *dpth, const char *datapath)
{
	unsigned int a=0;
	unsigned int b=0;
	unsigned int c=0;

	if(!datapath
	  || *datapath=='t') // The path used the tree style structure.
		return 0;

	if((sscanf(datapath, "%04X/%04X/%04X", &a, &b, &c))!=3)
		return -1;
	if(dpth->comp[0]==(int)a
	  && dpth->comp[1]==(int)b
	  && dpth->comp[2] > (int)c)
		return 0;
	if(dpth->comp[0]==(int)a
	  && dpth->comp[1] > (int)b)
		return 0;
	if(dpth->comp[0] > (int)a)
		return 0;

	dpth->comp[0]=a;
	dpth->comp[1]=b;
	dpth->comp[2]=c;
	return 0;
}
