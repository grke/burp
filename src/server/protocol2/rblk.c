#include "../../burp.h"
#include "../../alloc.h"
#include "../../cmd.h"
#include "../../fzp.h"
#include "../../hexmap.h"
#include "../../iobuf.h"
#include "../../log.h"
#include "../../prepend.h"
#include "../../protocol2/blk.h"
#include "rblk.h"

static ssize_t rblk_mem=0;
static ssize_t rblk_mem_max=0;

// For retrieving stored data.
struct rblk
{
	uint64_t hash_key;
	struct iobuf readbuf[DATA_FILE_SIG_MAX];
	uint16_t readbuflen;
	UT_hash_handle hh;
};

static void rblk_free_content(struct rblk *rblk)
{
	for(int j=0; j<DATA_FILE_SIG_MAX; j++)
	{
		rblk_mem-=rblk->readbuf[j].len;
		iobuf_free_content(&rblk->readbuf[j]);
	}
}

static void rblk_free(struct rblk **rblk)
{
/*
uint16_t datno;
char *x;
x=uint64_to_savepathstr_with_sig_uint((*rblk)->savepath, &datno);
printf(" free: %s\n", x);
*/
	rblk_free_content(*rblk);
	rblk_mem-=sizeof(struct rblk);
	free_v((void **)rblk);
}

static struct rblk *rblk_hash=NULL;

static struct rblk *rblk_hash_find(uint64_t savepath)
{
	struct rblk *rblk;
	HASH_FIND_INT(rblk_hash, &savepath, rblk);
	return rblk;
}

static void rblk_hash_add(struct rblk *rblk)
{
	HASH_ADD_INT(rblk_hash, hash_key, rblk);
}

static struct rblk *rblk_alloc(void)
{
	struct rblk *rblk;
	rblk=(struct rblk *)calloc_w(1, sizeof(struct rblk), __func__);
	if(rblk)
		rblk_mem+=sizeof(struct rblk);
	return rblk;
}

void rblks_init(ssize_t rblk_memory_max)
{
	rblk_mem_max=rblk_memory_max;
}

void rblks_free(void)
{
	struct rblk *tmp;
	struct rblk *rblk;

	HASH_ITER(hh, rblk_hash, rblk, tmp)
	{
		HASH_DEL(rblk_hash, rblk);
		rblk_free(&rblk);
	}
	rblk_hash=NULL;
}

static int rblks_free_one(void)
{
	uint64_t before=rblk_mem;
	struct rblk *tmp;
	struct rblk *rblk;

	HASH_ITER(hh, rblk_hash, rblk, tmp)
	{
		HASH_DEL(rblk_hash, rblk);
		rblk_free(&rblk);
		break;
	}
	if(before!=rblk_mem)
		return 0;
	return -1;
}

static int rblk_load_from_disk(struct rblk *rblk, const char *fulldatpath)
{
	int r;
	int ret=-1;
	int done=0;
	struct fzp *fzp=NULL;
	struct iobuf rbuf;

	iobuf_init(&rbuf);

	if(!(fzp=fzp_open(fulldatpath, "rb")))
		goto end;
	for(r=0; r<DATA_FILE_SIG_MAX; r++)
	{
		switch(iobuf_fill_from_fzp_data(&rbuf, fzp))
		{
			case 0: if(rbuf.cmd!=CMD_DATA)
				{
					logp("unknown cmd in %s: %c\n",
						__func__, rbuf.cmd);
					goto end;
				}
				iobuf_free_content(&rblk->readbuf[r]);
				iobuf_move(&rblk->readbuf[r], &rbuf);
				rblk_mem+=rblk->readbuf[r].len;
				continue;
			case 1: done++;
				break;
			default: goto end;
		}
		if(done) break;
	}
	rblk->readbuflen=r;
	ret=0;
end:
	fzp_close(&fzp);
	return ret;
}

static int rblk_init(struct rblk *rblk, struct blk *blk,
	uint64_t hash_key, const char *datpath, const char *savepathstr)
{
	int ret=-1;
	char *fulldatpath=NULL;

	rblk->hash_key=hash_key;
	if(!(fulldatpath=prepend_s(datpath, savepathstr)))
		goto end;
	logp("load: %s\n", savepathstr);
	if(rblk_load_from_disk(rblk, fulldatpath))
		goto end;
	ret=0;
end:
	free_w(&fulldatpath);
	return ret;
}

int rblk_retrieve_data(struct asfd *asfd, struct cntr *cntr,
	struct blk *blk, const char *datpath)
{
	uint16_t datno=0;
	uint64_t hash_key;
	char *savepathstr;
	struct rblk *rblk=NULL;

	hash_key=uint64_to_savepath_hash_key(blk->savepath);
	savepathstr=uint64_to_savepathstr_with_sig_uint(blk->savepath, &datno);

	if(!(rblk=rblk_hash_find(hash_key)))
	{
		if(!(rblk=rblk_alloc())
		  || rblk_init(rblk, blk, hash_key, datpath, savepathstr))
		{
			rblk_free(&rblk);
			return -1;
		}
		while(rblk_mem>rblk_mem_max)
		{
			if(rblks_free_one())
			{
				logw(asfd, cntr,
					"rblk_memory_max is too low!\n");
				break;
			}
		}
		rblk_hash_add(rblk);
	}

// printf("lookup: %s (%u)\n", savepathstr, datno);
	if(datno>rblk->readbuflen)
	{
		logp("dat index %d is greater than readbuflen: %d\n",
			datno, rblk->readbuflen);
		return -1;
	}
	blk->data=rblk->readbuf[datno].buf;
	blk->length=rblk->readbuf[datno].len;
// printf("length: %d\n", blk->length);

        return 0;
}
