#include "include.h"

int champ_chooser_init(const char *datadir, struct conf *conf)
{
	int ars;
	int ret=-1;
	gzFile zp=NULL;
	struct sbuf *sb=NULL;
	char *sparse_path=NULL;
	struct stat statp;
	struct candidate *candidate=NULL;

	// FIX THIS: scores is a global variable.
	if(!(scores=scores_alloc())) goto end;

	if(!(sb=sbuf_alloc(conf))
	  || !(sparse_path=prepend_s(datadir, "sparse"))
	  || (!lstat(sparse_path, &statp)
		&& !(zp=gzopen_file(sparse_path, "rb"))))
			goto end;
	while(zp)
	{
		// FIX THIS: second argument should be struct async for
		// the server child.
		if((ars=sbuf_fill_from_gzfile(sb, NULL,
			zp, NULL, NULL, conf))<0)
				goto end;
		else if(ars>0)
		{
			// Reached the end.
			break;
		}
		if(sb->path.cmd==CMD_MANIFEST)
		{
			if(!(candidate=candidates_add_new())) goto end;
			candidate->path=sb->path.buf;
			sb->path.buf=NULL;
		}
		else if(sb->path.cmd==CMD_FINGERPRINT)
		{
			if(sparse_add_candidate(sb->path.buf, candidate))
				goto end;
		}
		else
		{
			iobuf_log_unexpected(&sb->path, __func__);
			goto end;
		}
		sbuf_free_content(sb);
	}

	ret=0;
end:
	gzclose_fp(&zp);
	sbuf_free(sb);
	if(sparse_path) free(sparse_path);
	return ret;
}

int is_hook(const char *str)
{
	// FIX THIS: should work on bits, not just the character.
	return *str=='F';
}

static char *get_fq_path(const char *path)
{
	static char fq_path[24];
	snprintf(fq_path, sizeof(fq_path), "%s\n", path);
	return fq_path;
}

static int already_got_block(struct asfd *asfd, struct blk *blk)
{
	//static char *path;
	static struct hash_weak *hash_weak;

	// If already got, need to overwrite the references.
	if((hash_weak=hash_weak_find(blk->fingerprint)))
	{
		static struct hash_strong *hash_strong;
		if((hash_strong=hash_strong_find(
			hash_weak, blk->strong)))
		{
			snprintf(blk->save_path, sizeof(blk->save_path),
				"%s", get_fq_path(hash_strong->path));
//printf("FOUND: %s %s\n", blk->weak, blk->strong);
//printf("F");
			blk->got=GOT;
			asfd->in->got++;
			return 0;
		}
		else
		{
//      printf("COLLISION: %s %s\n", blk->weak, blk->strong);
//                      collisions++;
		}
	}

	blk->got=NOT_GOT;
//printf(".");

	// Set up the details of where the block will be saved.
/* This is going to be the job of the server child.
	if(!(path=dpth_mk(dpth))) return -1;
	snprintf(blk->save_path, sizeof(blk->save_path), "%s", path);
	if(dpth_incr_sig(dpth)) return -1;
*/

	return 0;
}

#define CHAMPS_MAX 10

int deduplicate(struct asfd *asfd, struct conf *conf)
{
	struct blk *blk;
	struct incoming *in=asfd->in;
	struct candidate *champ;
	struct candidate *champ_last=NULL;
	static int count=0;
	static int blk_count=0;

printf("in deduplicate()\n");

	incoming_found_reset(in);
	count=0;
	while((champ=candidates_choose_champ(in, champ_last)))
	{
		printf("Got champ: %s %d\n", champ->path, *(champ->score));
		if(hash_load(champ->path, conf)) return -1;
		if(++count==CHAMPS_MAX) break;
		champ_last=champ;
	}

	blk_count=0;
	for(blk=asfd->blist->head; blk; blk=blk->next)
	{
printf("try: %lu\n", blk->index);
		blk_count++;

		// FIX THIS - represents zero length block.
		if(!blk->fingerprint // All zeroes.
		  && !strcmp(blk->strong, "D41D8CD98F00B204E9800998ECF8427E"))
		{
			blk->got=GOT;
			in->got++;
			continue;
		}

		// If already got, this function will set blk->save_path
		// to be the location of the already got block.
		if(already_got_block(asfd, blk)) return -1;

printf("after agb: %lu %d\n", blk->index, blk->got);

		// If there are a number of consecutive blocks that we have
		// already got, help the client out and tell it to forget them,
		// because there is a limit to the number that it will keep
		// in memory.
		if(blk->got==GOT)
		{
			if(asfd->consecutive_got++>BLKS_CONSECUTIVE_NOTIFY)
			{
				asfd->wrap_up=blk->index;
				asfd->consecutive_got=0;
			}
		}
		else
			asfd->consecutive_got=0;
	}

	logp("%d %s found %d/%d incoming %s\n", count,
		count==1?"champ":"champs", in->got, blk_count,
		blk_count==1?"block":"blocks");
	//cntr_add_same_val(conf->cntr, CMD_DATA, in->got);

	// Start the incoming array again.
	in->size=0;
	// Destroy the deduplication hash table.
	hash_delete_all();

	return 0;
}
