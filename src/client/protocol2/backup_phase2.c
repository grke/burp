#include "../../burp.h"
#include "../../action.h"
#include "../../asfd.h"
#include "../../async.h"
#include "../../base64.h"
#include "../../cmd.h"
#include "../../cntr.h"
#include "../../iobuf.h"
#include "../../log.h"
#include "../../protocol2/blk.h"
#include "../../protocol2/blist.h"
#include "../../protocol2/rabin/rabin.h"
#include "../../slist.h"
#include "rabin_read.h"
#include "backup_phase2.h"

#define END_SIGS                0x01
#define END_BACKUP              0x02
#define END_REQUESTS            0x04
#define END_BLK_REQUESTS        0x08

static int add_to_file_requests(struct slist *slist, struct iobuf *rbuf)
{
	static uint64_t file_no=1;
	struct sbuf *sb;

	if(!(sb=sbuf_alloc(PROTO_2))) return -1;

	iobuf_move(&sb->path, rbuf);
	// Give it a number to simplify tracking.
	sb->protocol2->index=file_no++;
	slist_add_sbuf(slist, sb);

	return 0;
}

static int add_to_data_requests(struct blist *blist, struct iobuf *rbuf)
{
	uint64_t index;
	struct blk *blk;
	index=base64_to_uint64(rbuf->buf);

//printf("last_requested: %d\n", blist->last_requested->index);

	// Find the matching entry.
	for(blk=blist->last_requested; blk; blk=blk->next)
		if(index==blk->index) break;
	if(!blk)
	{
		logp("Could not find requested block %" PRIu64 "\n", index);
		return -1;
	}
	blk->requested=1;
	blist->last_requested=blk;
	//printf("Found %lu\n", index);
	return 0;
}

static int deal_with_read(struct iobuf *rbuf, struct slist *slist,
	struct cntr *cntr, uint8_t *end_flags)
{
	int ret=0;
	switch(rbuf->cmd)
	{
		/* Incoming file request. */
		case CMD_FILE:
		case CMD_METADATA:
			if(add_to_file_requests(slist, rbuf)) goto error;
			return 0;

		/* Incoming data block request. */
		case CMD_DATA_REQ:
			if(add_to_data_requests(slist->blist, rbuf)) goto error;
			goto end;

		/* Incoming control/message stuff. */
		case CMD_WRAP_UP:
		{
			int64_t wrap_up;
			struct blk *blk;
			struct blist *blist=slist->blist;
			from_base64(&wrap_up, rbuf->buf);
			for(blk=blist->head; blk; blk=blk->next)
			{
				if(blk->index==(uint64_t)wrap_up)
				{
					blist->last_requested=blk;
					blist->last_sent=blk;
					break;
				}
			}
			if(!blk)
			{
				logp("Could not find wrap up index: %016" PRIX64 "\n",
					wrap_up);
//				goto error;
			}
			goto end;
		}
		case CMD_MESSAGE:
		case CMD_WARNING:
		{
			log_recvd(rbuf, cntr, 0);
			goto end;
		}
		case CMD_GEN:
			if(!strcmp(rbuf->buf, "requests_end"))
			{
				(*end_flags)|=END_REQUESTS;
				goto end;
			}
			else if(!strcmp(rbuf->buf, "blk_requests_end"))
			{
				(*end_flags)|=END_BLK_REQUESTS;
				goto end;
			}
			else if(!strcmp(rbuf->buf, "backup_end"))
			{
				(*end_flags)|=END_BACKUP;
				goto end;
			}
			break;
		default:
			break;
	}

	iobuf_log_unexpected(rbuf, __func__);
error:
	ret=-1;
end:
	iobuf_free_content(rbuf);
	return ret;
}

static int add_to_blks_list(struct asfd *asfd, struct conf **confs,
	struct slist *slist)
{
	int just_opened=0;
	struct sbuf *sb=slist->last_requested;
	if(!sb) return 0;

	if(sb->protocol2->bfd.mode==BF_CLOSED)
	{
		char buf[32];
		struct cntr *cntr=NULL;
		if(confs) cntr=get_cntr(confs);
		switch(rabin_open_file(sb, asfd, cntr, confs))
		{
			case 1: // All OK.
				break;
			case 0: // Could not open file. Tell the server.
				base64_from_uint64(sb->protocol2->index, buf);
				if(asfd->write_str(asfd, CMD_INTERRUPT, buf))
					return -1;
				if(slist_del_sbuf(slist, sb))
					return -1;
				sbuf_free(&sb);
				return 0;
			default:
				return -1;
		}
		just_opened=1;
	}

	switch(blks_generate(sb, slist->blist, just_opened))
	{
		case 0: // All OK.
			break;
		case 1: // File ended.
			if(rabin_close_file(sb, asfd))
			{
				logp("Failed to close file %s\n",
					iobuf_to_printable(&sb->path));
				return -1;
			}
			slist->last_requested=sb->next;
			break;
		default:
			return -1;
	}

	return 0;
}

static void free_stuff(struct slist *slist)
{
	struct blk *blk;
	struct blist *blist=slist->blist;
	blk=blist->head;
	while(blk && blk!=blist->last_sent)
	{
		if(blk==slist->head->protocol2->bstart)
			slist->head->protocol2->bstart=NULL;
		if(blk==slist->head->protocol2->bend)
		{
			struct sbuf *sb;
			sb=slist->head;
			sb->protocol2->bend=NULL;
			slist->head=slist->head->next;
			if(!slist->head)
				slist->tail=NULL;
			sbuf_free(&sb);
		}
		blk=blk->next;
		blk_free(&blist->head);
		blist->head=blk;
	}
}

static void get_wbuf_from_data(struct conf **confs,
	struct iobuf *wbuf, struct slist *slist, uint8_t end_flags)
{
	struct blk *blk;
	struct blist *blist=slist->blist;

	for(blk=blist->last_sent; blk; blk=blk->next)
	{
		if(blk->requested)
		{
			iobuf_set(wbuf, CMD_DATA, blk->data, blk->length);
			blk->requested=0;
			blist->last_sent=blk;
			cntr_add(get_cntr(confs), CMD_DATA, 1);
			break;
		}
		else
		{
			cntr_add_same(get_cntr(confs), CMD_DATA);
			if(end_flags&END_BLK_REQUESTS)
			{
				// Force onwards when the server has said that
				// there are no more blocks to request.
				blist->last_sent=blk;
				continue;
			}
		}
		if(blk==blist->last_requested) break;
	}
	// Need to free stuff that is no longer needed.
	free_stuff(slist);
}

static int iobuf_from_blk_data(struct iobuf *wbuf, struct blk *blk)
{
	if(blk_md5_update(blk)) return -1;
	blk_to_iobuf_sig(blk, wbuf);
	return 0;
}

static int get_wbuf_from_blks(struct iobuf *wbuf,
	struct slist *slist, uint8_t *end_flags)
{
	struct sbuf *sb=slist->blks_to_send;

	if(!sb)
	{
		if((*end_flags)&END_REQUESTS && !((*end_flags)&END_SIGS))
		{
			iobuf_from_str(wbuf, CMD_GEN, (char *)"sigs_end");
			(*end_flags)|=END_SIGS;
		}
		return 0;
	}
	if(!sb->protocol2->bsighead) return 0;

	if(!(sb->flags & SBUF_SENT_STAT))
	{
		iobuf_copy(wbuf, &sb->attr);
		wbuf->cmd=CMD_ATTRIBS_SIGS; // hack
		sb->flags |= SBUF_SENT_STAT;
		return 0;
	}

	if(iobuf_from_blk_data(wbuf, sb->protocol2->bsighead)) return -1;

	// Move on.
	if(sb->protocol2->bsighead==sb->protocol2->bend)
	{
		slist->blks_to_send=sb->next;
		sb->protocol2->bsighead=sb->protocol2->bstart;
	}
	else
	{
		sb->protocol2->bsighead=sb->protocol2->bsighead->next;
	}
	return 0;
}

int backup_phase2_client_protocol2(struct asfd *asfd,
	struct conf **confs, int resume)
{
	int ret=-1;
	uint8_t end_flags=0;
	struct slist *slist=NULL;
	struct iobuf *rbuf=NULL;
	struct iobuf *wbuf=NULL;
	struct cntr *cntr=NULL;

	if(confs) cntr=get_cntr(confs);

	if(!asfd || !asfd->as)
	{
		logp("%s() called without async structs!\n", __func__);
		goto end;
	}

	logp("Phase 2 begin (send backup data)\n");
	logfmt("\n");

	if(!(slist=slist_alloc())
	  || !(wbuf=iobuf_alloc())
	  || blks_generate_init())
		goto end;
	rbuf=asfd->rbuf;

	if(!resume)
	{
		// Only do this bit if the server did not tell us to resume.
		if(asfd->write_str(asfd, CMD_GEN, "backupphase2")
		  || asfd_read_expect(asfd, CMD_GEN, "ok"))
			goto end;
	}
	else
	{
		// On resume, the server might update the client with cntr.
		if(cntr_recv(asfd, confs))
			goto end;
        }

	while(!(end_flags&END_BACKUP))
	{
		if(!wbuf->len)
		{
			get_wbuf_from_data(confs, wbuf, slist,
				end_flags);
			if(!wbuf->len)
			{
				if(get_wbuf_from_blks(wbuf, slist,
					&end_flags)) goto end;
			}
		}

		if(wbuf->len)
		{
			if(asfd->append_all_to_write_buffer(asfd, wbuf)
				==APPEND_ERROR)
					goto end;
		}
		if(asfd->as->read_write(asfd->as))
		{
			logp("error in %s\n", __func__);
			goto end;
		}

		if(rbuf->buf && deal_with_read(rbuf, slist, cntr, &end_flags))
			goto end;

		if(slist->head
		// Need to limit how many blocks are allocated at once.
		  && (!slist->blist->head
		   || slist->blist->tail->index
			- slist->blist->head->index<BLKS_MAX_IN_MEM)
		)
		{
			if(add_to_blks_list(asfd, confs, slist))
				goto end;
		}

		if(end_flags&END_BLK_REQUESTS)
		{
			// If got to the end of the file request list
			// and the last block of the last file, and
			// the write buffer is empty, we got to the end.
			if(slist->head==slist->tail)
			{
				if(!slist->tail
				  || slist->blist->last_sent==
					slist->tail->protocol2->bend)
				{
					if(!wbuf->len)
						break;
				}
			}

		}
	}

	if(asfd->write_str(asfd, CMD_GEN, "backup_end"))
		goto end;

	ret=0;
end:
	slist_free(&slist);
	blks_generate_free();
	if(wbuf)
	{
		// Write buffer did not allocate 'buf'.
		wbuf->buf=NULL;
		iobuf_free(&wbuf);
	}
	cntr_print_end(cntr);
	cntr_set_bytes(cntr, asfd);
	cntr_print(cntr, ACTION_BACKUP);
	if(ret) logp("Error in backup\n");
	logp("End backup\n");

	return ret;
}
