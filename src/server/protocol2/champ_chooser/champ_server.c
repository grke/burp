#include "../../../burp.h"
#include "../../../alloc.h"
#include "../../../asfd.h"
#include "../../../async.h"
#include "../../../cmd.h"
#include "../../../conf.h"
#include "../../../conffile.h"
#include "../../../fsops.h"
#include "../../../handy.h"
#include "../../../iobuf.h"
#include "../../../lock.h"
#include "../../../log.h"
#include "../../../protocol2/blist.h"
#include "../../../protocol2/blk.h"
#include "../../sdirs.h"
#include "candidate.h"
#include "champ_chooser.h"
#include "champ_server.h"
#include "dindex.h"
#include "incoming.h"
#include "scores.h"

#include <sys/un.h>

static int champ_chooser_new_client(struct async *as, struct conf **confs)
{
	int fd=-1;
	socklen_t t;
	struct asfd *newfd=NULL;
	struct sockaddr_un remote;
	struct blist *blist=NULL;

	t=sizeof(remote);
	if((fd=accept(as->asfd->fd, (struct sockaddr *)&remote, &t))<0)
	{
		logp("accept error in %s: %s\n", __func__, strerror(errno));
		goto error;
	}

	if(!(blist=blist_alloc())
	  || !(newfd=setup_asfd(as, "(unknown)", &fd, /*listen*/"")))
		goto error;
	newfd->blist=blist;
	newfd->set_timeout(newfd, get_int(confs[OPT_NETWORK_TIMEOUT]));

	logp("Connected to fd %d\n", newfd->fd);

	return 0;
error:
	close_fd(&fd);
	blist_free(&blist);
	return -1;
}

static int results_to_fd(struct asfd *asfd)
{
	static struct iobuf wbuf;
	struct blk *b;
	struct blk *l;

	if(!asfd->blist->last_index) return 0;

	// Need to start writing the results down the fd.
	for(b=asfd->blist->head; b && b!=asfd->blist->blk_to_dedup; b=l)
	{
		if(b->got==BLK_GOT)
		{
			// Need to write to fd.
			blk_to_iobuf_index_and_savepath(b, &wbuf);

			switch(asfd->append_all_to_write_buffer(asfd, &wbuf))
			{
				case APPEND_OK: break;
				case APPEND_BLOCKED:
					asfd->blist->head=b;
					return 0; // Try again later.
				default: return -1;
			}
		}
		else
		{
			// If the last in the sequence is BLK_NOT_GOT,
			// Send a 'wrap_up' message.
			if(!b->next || b->next==asfd->blist->blk_to_dedup)
			{
				blk_to_iobuf_wrap_up(b, &wbuf);
				switch(asfd->append_all_to_write_buffer(asfd,
					&wbuf))
				{
					case APPEND_OK: break;
					case APPEND_BLOCKED:
						asfd->blist->head=b;
						return 0; // Try again later.
					default: return -1;
				}
			}
		}
		l=b->next;
		blk_free(&b);
	}

	asfd->blist->head=b;
	if(!b) asfd->blist->tail=NULL;
	return 0;
}

static int deduplicate_maybe(struct asfd *asfd,
	struct blk *blk, const char *directory, struct scores *scores)
{
	if(!asfd->in && !(asfd->in=incoming_alloc()))
		return -1;

	if(blk_fingerprint_is_hook(blk))
	{
		if(incoming_grow_maybe(asfd->in))
			return -1;
		asfd->in->fingerprints[asfd->in->size-1]=blk->fingerprint;
	}
	if(++(asfd->blkcnt)<MANIFEST_SIG_MAX)
		return 0;
	asfd->blkcnt=0;

	if(deduplicate(asfd, directory, scores)<0)
		return -1;

	return 0;
}

#ifndef UTEST
static
#endif
int champ_server_deal_with_rbuf_sig(struct asfd *asfd,
	const char *directory, struct scores *scores)
{
	struct blk *blk;
	if(!(blk=blk_alloc())) return -1;

	blist_add_blk(asfd->blist, blk);

	if(!asfd->blist->blk_to_dedup)
		asfd->blist->blk_to_dedup=blk;

	if(blk_set_from_iobuf_sig(blk, asfd->rbuf))
		return -1;

	//logp("Got fingerprint from %d: %lu - %lu\n",
	//	asfd->fd, blk->index, blk->fingerprint);

	return deduplicate_maybe(asfd, blk, directory, scores);
}

static int deal_with_client_rbuf(struct asfd *asfd, const char *directory,
	struct scores *scores)
{
	if(asfd->rbuf->cmd==CMD_GEN)
	{
		if(!strncmp_w(asfd->rbuf->buf, "cname:"))
		{
			struct iobuf wbuf;
			free_w(&asfd->desc);
			if(!(asfd->desc=strdup_w(asfd->rbuf->buf
				+strlen("cname:"), __func__)))
					goto error;
			logp("%s: fd %d\n", asfd->desc, asfd->fd);
			iobuf_set(&wbuf, CMD_GEN,
				(char *)"cname ok", strlen("cname ok"));

			if(asfd->write(asfd, &wbuf))
				goto error;
		}
		else if(!strncmp_w(asfd->rbuf->buf, "sigs_end"))
		{
			//printf("Was told no more sigs\n");
			if(deduplicate(asfd, directory, scores)<0)
				goto error;
		}
		else
		{
			iobuf_log_unexpected(asfd->rbuf, __func__);
			goto error;
		}
	}
	else if(asfd->rbuf->cmd==CMD_SIG)
	{
		if(champ_server_deal_with_rbuf_sig(asfd, directory, scores))
			goto error;
	}
	else if(asfd->rbuf->cmd==CMD_MANIFEST)
	{
		// Client has completed a manifest file. Want to start using
		// it as a dedup candidate now.
		if(candidate_add_fresh(asfd->rbuf->buf, directory, scores))
			goto error;
	}
	else
	{
		iobuf_log_unexpected(asfd->rbuf, __func__);
		goto error;
	}
	iobuf_free_content(asfd->rbuf);
	return 0;
error:
	iobuf_free_content(asfd->rbuf);
	return -1;
}

int champ_chooser_server(struct sdirs *sdirs, struct conf **confs,
	int resume)
{
	int s;
	int ret=-1;
	int len;
	struct asfd *asfd=NULL;
	struct sockaddr_un local;
	struct lock *lock=NULL;
	struct async *as=NULL;
	int started=0;
	struct scores *scores=NULL;
	const char *directory=get_string(confs[OPT_DIRECTORY]);

	if(!(lock=lock_alloc_and_init(sdirs->champlock))
	  || build_path_w(sdirs->champlock))
		goto end;
	lock_get(lock);
	switch(lock->status)
	{
		case GET_LOCK_GOT:
			log_fzp_set(sdirs->champlog, confs);
			logp("Got champ lock for dedup_group: %s\n",
				get_string(confs[OPT_DEDUP_GROUP]));
			break;
		case GET_LOCK_NOT_GOT:
		case GET_LOCK_ERROR:
		default:
			//logp("Did not get champ lock\n");
			goto end;
	}

	if((s=socket(AF_UNIX, SOCK_STREAM, 0))<0)
	{
		logp("socket error in %s: %s\n", __func__, strerror(errno));
		goto end;
	}

	memset(&local, 0, sizeof(struct sockaddr_un));
	local.sun_family=AF_UNIX;
	snprintf(local.sun_path, sizeof(local.sun_path),
		"%s", sdirs->champsock);
	len=strlen(local.sun_path)+sizeof(local.sun_family)+1;
	unlink(sdirs->champsock);
	if(bind(s, (struct sockaddr *)&local, len)<0)
	{
		logp("bind error in %s: %s\n", __func__, strerror(errno));
		goto end;
	}

	if(listen(s, 5)<0)
	{
		logp("listen error in %s: %s\n", __func__, strerror(errno));
		goto end;
	}

	if(!(as=async_alloc())
	  || as->init(as, 0)
	  || !(asfd=setup_asfd(as, "champ chooser main socket", &s,
		/*listen*/"")))
			goto end;
	asfd->fdtype=ASFD_FD_SERVER_LISTEN_MAIN;

	// I think that this is probably the best point at which to run a
	// cleanup job to delete unused data files, because no other process
	// can fiddle with the dedup_group at this point.
	// Cannot do it on a resume, or it will delete files that are
	// referenced in the backup we are resuming.
	if(delete_unused_data_files(sdirs, resume))
		goto end;

	// Load the sparse indexes for this dedup group.
	if(!(scores=champ_chooser_init(sdirs->data)))
		goto end;

	while(1)
	{
		for(asfd=as->asfd->next; asfd; asfd=asfd->next)
		{
			if(!asfd->blist->head
			  || asfd->blist->head->got==BLK_INCOMING) continue;
			if(results_to_fd(asfd)) goto end;
		}

		int removed;

		switch(as->read_write(as))
		{
			case 0:
				// Check the main socket last, as it might add
				// a new client to the list.
				for(asfd=as->asfd->next; asfd; asfd=asfd->next)
				{
					while(asfd->rbuf->buf)
					{
						if(deal_with_client_rbuf(asfd,
							directory, scores))
								goto end;
						// Get as much out of the
						// readbuf as possible.
						if(asfd->parse_readbuf(asfd))
							goto end;
					}
				}
				if(as->asfd->new_client)
				{
					// Incoming client.
					as->asfd->new_client=0;
					if(champ_chooser_new_client(as, confs))
						goto end;
					started=1;
				}
				break;
			default:
				removed=0;
				// Maybe one of the fds had a problem.
				// Find and remove it and carry on if possible.
				for(asfd=as->asfd->next; asfd; )
				{
					struct asfd *a;
					if(!asfd->want_to_remove)
					{
						asfd=asfd->next;
						continue;
					}
					as->asfd_remove(as, asfd);
					logp("%s: disconnected fd %d\n",
						asfd->desc, asfd->fd);
					a=asfd->next;
					asfd_free(&asfd);
					asfd=a;
					removed++;
				}
				if(removed) break;
				// If we got here, there was no fd to remove.
				// It is a fatal error.
				goto end;
		}
				
		if(started && !as->asfd->next)
		{
			logp("All clients disconnected.\n");
			ret=0;
			break;
		}
	}

end:
	logp("champ chooser exiting: %d\n", ret);
	champ_chooser_free(&scores);
	log_fzp_set(NULL, confs);
	async_free(&as);
	asfd_free(&asfd); // This closes s for us.
	close_fd(&s);
	unlink(sdirs->champsock);
// FIX THIS: free asfds.
	lock_release(lock);
	lock_free(&lock);
	return ret;
}

// The return code of this is the return code of the standalone process.
int champ_chooser_server_standalone(struct conf **globalcs)
{
	int ret=1;
	struct sdirs *sdirs=NULL;
	struct conf **cconfs=NULL;
	const char *orig_client=get_string(globalcs[OPT_ORIG_CLIENT]);

	if(!(cconfs=confs_alloc()))
		goto end;
	confs_init(cconfs);
	// We need to be given a client name and load the relevant server side
	// clientconfdir file, because various settings may be overridden
	// there.
	if(set_string(cconfs[OPT_CNAME], orig_client)
	  || conf_load_clientconfdir(globalcs, cconfs)
	  || !(sdirs=sdirs_alloc())
	  || sdirs_init_from_confs(sdirs, cconfs)
	  || champ_chooser_server(sdirs, cconfs, 0 /* resume */))
		goto end;
	ret=0;
end:
	confs_free(&cconfs);
	sdirs_free(&sdirs);
	return ret;
}
