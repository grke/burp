#include "include.h"
#include "../../cmd.h"

// For retrieving stored data.
struct rblk
{
	char *datpath;
	struct iobuf readbuf[DATA_FILE_SIG_MAX];
	unsigned int readbuflen;
};

#define RBLK_MAX	10

// Return 0 on OK, -1 on error, 1 when there is no more to read.
static int read_next_data(FILE *fp, struct rblk *rblk, int ind, int r)
{
	enum cmd cmd=CMD_ERROR;
	size_t bytes;
	unsigned int len;
	char buf[5];
	// FIX THIS: Check for the appropriate return value that means there
	// is no more to read.
	if(fread(buf, 1, 5, fp)!=5) return 1;
	if((sscanf(buf, "%c%04X", (uint8_t *)&cmd, &len))!=2)
	{
		logp("sscanf failed in %s: %s\n", __func__, buf);
		return -1;
	}
	if(cmd!=CMD_DATA)
	{
		logp("unknown cmd in %s: %c\n", __func__, cmd);
		return -1;
	}
	if(!(rblk[ind].readbuf[r].buf=
		(char *)realloc_w(rblk[ind].readbuf[r].buf, len, __func__)))
		return -1;
	if((bytes=fread(rblk[ind].readbuf[r].buf, 1, len, fp))!=len)
	{
		logp("Short read: %d wanted: %d\n", (int)bytes, (int)len);
		return -1;
	}
	rblk[ind].readbuf[r].len=len;
	//printf("read: %d:%d %04X\n", r, len, r);

	return 0;
}

static int load_rblk(struct rblk *rblks, int ind, const char *datpath)
{
	int r;
	FILE *dfp;
	free_w(&rblks[ind].datpath);
	if(!(rblks[ind].datpath=strdup_w(datpath, __func__)))
		return -1;
	printf("swap %d to: %s\n", ind, datpath);

	if(!(dfp=open_file(datpath, "rb"))) return -1;
	for(r=0; r<DATA_FILE_SIG_MAX; r++)
	{
		switch(read_next_data(dfp, rblks, ind, r))
		{
			case 0: continue;
			case 1: break;
			case -1:
			default:
				return -1;
		}
	}
	rblks[ind].readbuflen=r;
	fclose(dfp);
	return 0;
}

static struct rblk *get_rblk(struct rblk *rblks, const char *datpath)
{
	static int current_ind=0;
	static int last_swap_ind=0;
	int ind=current_ind;

	while(1)
	{
		if(!rblks[ind].datpath)
		{
			if(load_rblk(rblks, ind, datpath)) return NULL;
			last_swap_ind=ind;
			current_ind=ind;
			return &rblks[current_ind];
		}
		else if(!strcmp(rblks[ind].datpath, datpath))
		{
			current_ind=ind;
			return &rblks[current_ind];
		}
		ind++;
		if(ind==RBLK_MAX) ind=0;
		if(ind==current_ind)
		{
			// Went through all RBLK_MAX entries.
			// Replace the oldest one.
			ind=last_swap_ind+1;
			if(ind==RBLK_MAX) ind=0;
			if(load_rblk(rblks, ind, datpath)) return NULL;
			last_swap_ind=ind;
			current_ind=ind;
			return &rblks[current_ind];
		}
	}
}

int rblk_retrieve_data(const char *datpath, struct blk *blk)
{
	static char fulldatpath[256]="";
	static struct rblk *rblks=NULL;
	char *cp;
	unsigned int datno;
	struct rblk *rblk;

	snprintf(fulldatpath, sizeof(fulldatpath),
		"%s/%s", datpath, bytes_to_savepathstr_with_sig(blk->savepath));

//printf("x: %s\n", fulldatpath);
	if(!(cp=strrchr(fulldatpath, '/')))
	{
		logp("Could not parse data path: %s\n", fulldatpath);
		return -1;
	}
	*cp=0;
	cp++;
	datno=strtoul(cp, NULL, 16);
//printf("y: %s\n", fulldatpath);

	if(!rblks
	  && !(rblks=(struct rblk *)
		calloc_w(RBLK_MAX, sizeof(struct rblk), __func__)))
			return -1;

	if(!(rblk=get_rblk(rblks, fulldatpath)))
	{
		return -1;
	}

//	printf("lookup: %s (%s)\n", fulldatpath, cp);
	if(datno>rblk->readbuflen)
	{
		logp("dat index %d is greater than readbuflen: %d\n",
			datno, rblk->readbuflen);
		return -1;
	}
	blk->data=rblk->readbuf[datno].buf;
	blk->length=rblk->readbuf[datno].len;
//	printf("length: %d\n", blk->length);

        return 0;
}
