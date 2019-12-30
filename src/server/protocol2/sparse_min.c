#include "../../burp.h"
#include "../../alloc.h"
#include "../../cmd.h"
#include "../../cstat.h"
#include "../../fsops.h"
#include "../../iobuf.h"
#include "../../lock.h"
#include "../../log.h"
#include "../../prepend.h"
#include "../sdirs.h"
#include "sparse_min.h"

#include <uthash.h>

struct cname_backup
{
	uint8_t keep;
	uint8_t delete;
	char *id;
	char *cname;
	char *backup;
	uint64_t size;
	UT_hash_handle hh;
};
struct cname_backup *chash_table=NULL;

static void cname_backup_free(struct cname_backup **cb)
{
	if(!cb || !*cb)
		return;
	free_w(&(*cb)->cname);
	free_w(&(*cb)->backup);
	free_w(&(*cb)->id);
	free_v((void **)cb);
}

/*
static void dump_table()
{
	uint64_t s=0;
	struct cname_backup *tmp;
	struct cname_backup *x;

	HASH_ITER(hh, chash_table, x, tmp)
	{
printf("HERE %d %d - %s %s: %" PRIu64 "\n",
	x->keep, x->delete,
	x->cname, x->backup, x->size);
s+=x->size;
	}
printf("s: %" PRIu64 "\n", s);
}
*/

static void free_table()
{
	struct cname_backup *tmp;
	struct cname_backup *x;

	HASH_ITER(hh, chash_table, x, tmp)
	{
		HASH_DEL(chash_table, x);
		cname_backup_free(&x);
	}
	chash_table=NULL;
}

// This gets the oldest one that is not marked to keep or to delete.
// Does not distinguish between different clients.
static struct cname_backup *find_one_to_delete()
{
	struct cname_backup *tmp=NULL;
	struct cname_backup *best=NULL;
	struct cname_backup *cand=NULL;

	if(!chash_table)
		return NULL;

	HASH_ITER(hh, chash_table, cand, tmp)
	{
		if(cand->delete || cand->keep)
			continue;
		if(!best)
		{
			best=cand;
			continue;
		}
		if(strcmp(cand->backup, best->backup)<0)
			best=cand;
	}
	return best;
}

static int parse_man(
	char *man,
	char **id,
	char **cname,
	char **backup
)
{
	int t=0;
	char *tok=NULL;
	if(!(tok=strtok(man, "/")))
	{
		logp("Could not tokenise %s in %s\n", man, __func__);
		return -1;
	}
	while((tok=strtok(NULL, "/")))
	{
		t++;
		if(t==2)
			*cname=tok;
		else if(t==3)
			*backup=tok;
	}
	if(!*cname || !*backup)
	{
		logp("Could not get cname/backup in %s\n", __func__);
		return -1;
	}
	if(!(*id=prepend_s(*cname, *backup)))
		return -1;
	return 0;
}

static int add_to_chash_table(
	char *man,
	int fsize
) {
	int ret=-1;
	char *id=NULL;
	char *cname=NULL;
	char *backup=NULL;
	struct cname_backup *cnb=NULL;

	if(parse_man(man, &id, &cname, &backup))
		goto end;

	HASH_FIND_STR(chash_table, id, cnb);
	if(cnb)
		free_w(&id);
	else
	{
		if(!(cnb=calloc_w(1, sizeof(*cnb), __func__))
		  || !(cnb->cname=strdup_w(cname, __func__))
		  || !(cnb->backup=strdup_w(backup, __func__)))
			goto end;
		cnb->size=0;
		cnb->id=id;
		id=NULL;
		HASH_ADD_KEYPTR(hh, chash_table,
			cnb->id, strlen(cnb->id), cnb);
	}
	cnb->size+=fsize;
	ret=0;
end:
	if(ret)
		cname_backup_free(&cnb);
	free_w(&id);
	return ret;
}

static void keep_most_recent_of_each_client(struct cstat *clist)
{
	struct cstat *c;
	if(!chash_table)
		return;
	for(c=clist; c; c=c->next)
	{
		struct cname_backup *tmp=NULL;
		struct cname_backup *best=NULL;
		struct cname_backup *cand=NULL;

		HASH_ITER(hh, chash_table, cand, tmp)
		{
			if(strcmp(cand->cname, c->name))
				continue;
			if(!best)
			{
				best=cand;
				continue;
			}
			if(strcmp(cand->backup, best->backup)>0)
				best=cand;
		}
		if(best)
			best->keep=1;
	}
}

static void mark_deletable(struct cstat *clist, uint64_t need)
{
	uint64_t got=0;
	struct cname_backup *cnb=NULL;

	keep_most_recent_of_each_client(clist);
	while(1)
	{
		if((cnb=find_one_to_delete()))
		{
			cnb->delete=1;
			got+=cnb->size;
			if(got>=need)
				break;
		}
		else
		{
			// Did not get enough. Do our best anyway.
			break;
		}
	}
	logp("     will prune: %"PRIu64 " bytes\n", got);
}

static char *get_global_sparse_tmp(const char *global_sparse)
{
	return prepend_n(global_sparse, "tmp", strlen("tmp"), ".");
}

static int do_minimise(const char *global_sparse)
{
	int ret=-1;
        struct iobuf rbuf;
	struct fzp *fzp=NULL;
	struct fzp *fzp_tmp=NULL;
	char *id=NULL;
	char *copy=NULL;
	char *junk1=NULL;
	char *junk2=NULL;
	char *sparse_tmp=NULL;
	int delete=0;

	if(!(sparse_tmp=get_global_sparse_tmp(global_sparse)))
		goto end;

	memset(&rbuf, 0, sizeof(struct iobuf));
	if(!(fzp=fzp_gzopen(global_sparse, "rb")))
		goto end;
	if(!(fzp_tmp=fzp_gzopen(sparse_tmp, "wb")))
		goto end;
	while(1)
	{
		iobuf_free_content(&rbuf);
		switch(iobuf_fill_from_fzp(&rbuf, fzp))
		{
			case 1:
				// All OK.
				if(fzp_close(&fzp_tmp))
				{
					logp("error closing %s in %s\n",
						sparse_tmp, __func__);
					goto end;
				}
				if(do_rename(sparse_tmp, global_sparse))
					goto end;
				ret=0;
				goto end;
			case -1:
				goto end; // Error.
		}

		if(rbuf.cmd==CMD_MANIFEST)
		{
			struct cname_backup *cnb=NULL;
			if(!(copy=strdup_w(rbuf.buf, __func__)))
				goto end;
			// Do not pass in rbuf here, as we want to write
			// it back to the new file, and parse_man destroys it
			// with strtok.
			if(parse_man(copy, &id, &junk1, &junk2))
				goto end;
			HASH_FIND_STR(chash_table, id, cnb);
			if(cnb && cnb->delete)
				delete=1;
			else
			{
				delete=0;
				if(iobuf_send_msg_fzp(&rbuf, fzp_tmp))
					goto end;
				//fzp_printf(fzp_tmp, "%c%04lX%s\n", CMD_MANIFEST,
				//	strlen(copy), copy);
			}
			free_w(&id);
			free_w(&copy);
		}
		else if(rbuf.cmd==CMD_FINGERPRINT)
		{
			if(delete)
				continue;
			if(iobuf_send_msg_fzp(&rbuf, fzp_tmp))
				goto end;
		}
	}

end:
	fzp_close(&fzp);
	fzp_close(&fzp_tmp);
	free_w(&id);
	free_w(&copy);
	free_w(&sparse_tmp);
	iobuf_free_content(&rbuf);
	return ret;
}

static int load_chash_table(const char *global_sparse, uint64_t *tsize)
{
	int ret=-1;
        struct iobuf rbuf;
	struct fzp *fzp=NULL;
	int fsize=0;
	char *man=NULL;

	memset(&rbuf, 0, sizeof(struct iobuf));
	if(!(fzp=fzp_gzopen(global_sparse, "rb")))
		goto end;
	while(1)
	{
		iobuf_free_content(&rbuf);
		switch(iobuf_fill_from_fzp(&rbuf, fzp))
		{
			case 1:
				if(man)
				{
					if(add_to_chash_table(man, fsize))
						goto end;
					free_w(&man);
				}
				// All OK.
				ret=0;
				goto end;
			case -1:
				goto end; // Error.
		}

		if(rbuf.cmd==CMD_MANIFEST)
		{
			if(man)
			{
				if(add_to_chash_table(man, fsize))
					goto end;
				free_w(&man);
			}
			man=rbuf.buf;
			rbuf.buf=NULL;

			// Starting a new one.
			fsize=rbuf.len+6; // 5 leading chars, plus newline.
			*tsize+=rbuf.len+6; // 5 leading chars, plus newline.
		}
		else if(rbuf.cmd==CMD_FINGERPRINT)
		{
			// Each fingerprint is 14 bytes.
			fsize+=14;
			*tsize+=14;
		}
	}

end:
	fzp_close(&fzp);
	iobuf_free_content(&rbuf);
	free_w(&man);
	return ret;
}

int sparse_minimise(
	struct conf **conf,
	const char *global_sparse,
	struct lock *sparse_lock,
	struct cstat *clist
) {
	int ret=-1;
	uint64_t need=0;
	uint64_t tsize=0;
	uint64_t size_max=get_uint64_t(conf[OPT_SPARSE_SIZE_MAX]);

	if(sparse_lock->status!=GET_LOCK_GOT)
	{
		logp("Was not given a valid lock in %s()!", __func__);
		goto end;
	}

	if(load_chash_table(global_sparse, &tsize))
		goto end;
	logp("sparse_size_max: %" PRIu64 " bytes\n", size_max);
	logp("    actual size: %" PRIu64 " bytes\n", tsize);
	if(tsize<=size_max)
	{
		logp("Do not need to prune\n");
		ret=0;
		goto end;
	}
	need=tsize-size_max;
	logp("     too big by: %" PRIu64 " bytes\n", need);
	mark_deletable(clist, need);
	ret=do_minimise(global_sparse);
end:
	free_table();
	return ret;
}
