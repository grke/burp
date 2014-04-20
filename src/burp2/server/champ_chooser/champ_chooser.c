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

	if(!(sb=sbuf_alloc(conf))
	  || (!scores && !(scores=scores_alloc()))
	  || !(sparse_path=prepend_s(datadir, "sparse"))
	  || (!lstat(sparse_path, &statp)
		&& !(zp=gzopen_file(sparse_path, "rb"))))
			goto end;
	while(zp)
	{
		if((ars=sbuf_fill_from_gzfile(sb, zp, NULL, NULL, conf))<0)
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
			iobuf_log_unexpected(&sb->path, __FUNCTION__);
			goto end;
		}
		sbuf_free_content(sb);
	}

	if(scores_grow(scores, candidates_len)) goto end;
	candidates_set_score_pointers(candidates, candidates_len, scores);
	scores_reset(scores);

//	dump_scores("init", scores, scores->size);

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

static int already_got_block(struct blk *blk, struct dpth *dpth)
{
	static char *path;
	static struct weak_entry *weak_entry;

	// If already got, need to overwrite the references.
	if((weak_entry=find_weak_entry(blk->fingerprint)))
	{
		static struct strong_entry *strong_entry;
		if((strong_entry=find_strong_entry(weak_entry, blk->strong)))
		{
			snprintf(blk->save_path, sizeof(blk->save_path),
				"%s", get_fq_path(strong_entry->path));
//printf("FOUND: %s %s\n", blk->weak, blk->strong);
//printf("F");
			blk->got=GOT;
			in->got++;
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
	if(!(path=dpth_mk(dpth))) return -1;
	snprintf(blk->save_path, sizeof(blk->save_path), "%s", path);
	if(dpth_incr_sig(dpth)) return -1;

	return 0;
}

#define CHAMPS_MAX 10

int deduplicate(struct blk *blks, struct dpth *dpth, struct conf *conf, uint64_t *wrap_up)
{
	struct blk *blk;
	struct candidate *champ;
	struct candidate *champ_last=NULL;
	static int consecutive_got=0;
	static int count=0;
	static int blk_count=0;

//printf("in deduplicate()\n");

	incoming_found_reset(in);
	count=0;
	while((champ=candidates_choose_champ(in, champ_last)))
	{
//		printf("Got champ: %s %d\n", champ->path, *(champ->score));
		if(hash_load(champ->path, conf)) return -1;
		if(++count==CHAMPS_MAX) break;
		champ_last=champ;
	}

	blk_count=0;
	for(blk=blks; blk; blk=blk->next)
	{
//printf("try: %d\n", blk->index);
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
		if(already_got_block(blk, dpth)) return -1;

//printf("after agb: %lu %d\n", blk->index, blk->got);

		// If there are a number of consecutive blocks that we have
		// already got, help the client out and tell it to forget them,
		// because there is a limit to the number that it will keep
		// in memory.
		if(blk->got==GOT)
		{
			if(consecutive_got++>BLKS_CONSECUTIVE_NOTIFY)
			{
				*wrap_up=blk->index;
				consecutive_got=0;
			}
		}
		else
			consecutive_got=0;
	}

	logp("%d %s found %d/%d incoming %s\n", count,
		count==1?"champ":"champs", in->got, blk_count,
		blk_count==1?"block":"blocks");
	cntr_add_same_val(conf->cntr, CMD_DATA, in->got);

	// Start the incoming array again.
	in->size=0;
	// Destroy the deduplication hash table.
	hash_delete_all();

	return 0;
}

int deduplicate_maybe(struct blk *blk, struct dpth *dpth,
	struct conf *conf, uint64_t *wrap_up)
{
	static int count=0;
	static struct blk *blks=NULL;

	if(!blks && !(blks=blk)) return -1;
	if(!in && !(in=incoming_alloc())) return -1;

	blk->fingerprint=strtoull(blk->weak, 0, 16);
	if(is_hook(blk->weak))
	{
		if(incoming_grow_maybe(in)) return -1;
		in->weak[in->size-1]=blk->fingerprint;
	}
	if(++count<MANIFEST_SIG_MAX) return 0;
	count=0;

	if(deduplicate(blks, dpth, conf, wrap_up)<0) return -1;
	blks=NULL;

	return 0;
}

#include <sys/un.h>

typedef struct clifd clifd_t;

struct clifd
{
	int fd;
	struct incoming *in;
	struct scores *scores;
	struct clifd *next;
};

static int champ_chooser_incoming_client(int s, struct clifd **clifds)
{
	socklen_t t;
	struct clifd *newfd=NULL;
	struct sockaddr_un remote;

	if(!(newfd=(struct clifd *)calloc(1, sizeof(struct clifd))))
	{
		log_out_of_memory(__func__);
		goto error;
	}

	t=sizeof(remote);
	if((newfd->fd=accept(s, (struct sockaddr *)&remote, &t))<0)
	{
		logp("accept error in %s: %s\n",
			__func__, strerror(errno));
		goto error;
	}
	newfd->next=*clifds;
	*clifds=newfd;

	printf("Connected to fd %d\n", newfd->fd);

	return 0;
error:
	if(newfd) free(newfd);
	return -1;
}

static int champ_loop(int s, struct clifd **clifds, struct conf *conf)
{
	int mfd=-1;
	fd_set fsr;
	fd_set fsw;
	fd_set fse;
	struct clifd *c;
	struct timeval tval;

	FD_ZERO(&fsr);
	FD_ZERO(&fsw);

	tval.tv_sec=1;
	tval.tv_usec=0;

	add_fd_to_sets(s, &fsr, NULL, &fse, &mfd);
	for(c=*clifds; c; c=c->next)
		add_fd_to_sets(c->fd, &fsr, NULL, &fse, &mfd);

	if(select(mfd+1, &fsr, NULL, &fse, &tval)<0)
	{
		if(errno!=EAGAIN && errno!=EINTR)
		{
			logp("select error in normal part of %s: %s\n",
				__func__, strerror(errno));
			goto error;
		}
	}

	// Check clifds first, as adding an incoming client below will add
	// another clifd to the list.
	for(c=*clifds; c; c=c->next)
	{
		if(FD_ISSET(c->fd, &fse))
			continue;
		if(FD_ISSET(c->fd, &fsr))
		{
			printf("%d is ready to read\n", c->fd);
		}
	}

	if(FD_ISSET(s, &fse))
	{
		// Happens when a client exits.
		return 0;
	}

	if(FD_ISSET(s, &fsr))
	{
		// Incoming client.
		if(champ_chooser_incoming_client(s, clifds))
			goto error;
	}

	return 0;
error:
	return -1;
}

static int champ_chooser_child(struct sdirs *sdirs, struct conf *conf)
{
	int s;
	int len;
	int ret;
	struct sockaddr_un local;
	struct clifd *clifds=NULL;

	printf("%d: champ child\n", getpid());

	if((s=socket(AF_UNIX, SOCK_STREAM, 0))<0)
	{
		logp("socket error in %s: %s\n",
			__FUNCTION__, strerror(errno));
		return -1;
	}

	local.sun_family=AF_UNIX;
	strcpy(local.sun_path, sdirs->champsock);
	unlink(local.sun_path);
	len=strlen(local.sun_path)+sizeof(local.sun_family);
	if(bind(s, (struct sockaddr *)&local, len)<0)
	{
		logp("bind error in %s: %s\n",
			__FUNCTION__, strerror(errno));
		return -1;
	}

	if(listen(s, conf->max_children)<0)
	{
		logp("listen error in %s: %s\n",
			__FUNCTION__, strerror(errno));
		return -1;
	}

	while(!champ_loop(s, &clifds, conf)) { }
	close_fd(&s);

	unlink(sdirs->champsock);
// FIX THIS: free clisocks.
	return ret;
}

static int champ_chooser_fork(struct sdirs *sdirs, struct conf *conf)
{
	pid_t childpid=-1;

	switch((childpid=fork()))
	{
		case -1:
			logp("fork failed in %s: %s\n",
				__FUNCTION__, strerror(errno));
			return -1;
		case 0:
			// Child.
			set_logfp(NULL, conf);
			switch(champ_chooser_child(sdirs, conf))
			{
				case 0: exit(0);
				default: exit(1);
			}
		default:
			// Parent.
			logp("forked champ chooser pid %d\n", childpid);
			return 0;
	}
}

int connect_to_champ_chooser(struct sdirs *sdirs, struct conf *conf)
{
	int len;
	int s=-1;
	int tries=0;
	int tries_max=3;
	struct sockaddr_un remote;

	if((s=socket(AF_UNIX, SOCK_STREAM, 0))<0)
	{
		logp("socket error in %s: %s\n",
			__FUNCTION__, strerror(errno));
		return -1;
	}

	printf("Trying to connect...\n");

	remote.sun_family=AF_UNIX;
	strcpy(remote.sun_path, sdirs->champsock);
	len=strlen(remote.sun_path)+sizeof(remote.sun_family);

	while(tries++<tries_max)
	{
		int sleeptimeleft=3;
		if(connect(s, (struct sockaddr *)&remote, len)<0)
		{
			if(errno==ENOENT)
			{
				// Path did not exist.
				// Try to fork a new champ chooser process and
				// try again.
				logp("Champ chooser socket does not exist.\n");
				if(champ_chooser_fork(sdirs, conf)) break;
			}
			else
			{
				logp("connect error in %s: %d %s\n",
					__FUNCTION__, errno, strerror(errno));
			}
		}
		else
		{
			logp("Connected to champ chooser.\n");
			return s;
		}

		// SIGCHLDs may be interrupting.
		sleeptimeleft=3;
		while(sleeptimeleft>0) sleeptimeleft=sleep(sleeptimeleft);
	}

	logp("Could not connect to champ chooser via %s after %d attempts.",
		sdirs->champsock, tries);

	return -1;
}
