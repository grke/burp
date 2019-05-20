#include "../../burp.h"
#include "../../alloc.h"
#include "../../asfd.h"
#include "../../async.h"
#include "../../attribs.h"
#include "../../base64.h"
#include "../../cmd.h"
#include "../../cntr.h"
#include "../../cstat.h"
#include "../../handy.h"
#include "../../hexmap.h"
#include "../../iobuf.h"
#include "../../log.h"
#include "../../server/manio.h"
#include "../../protocol2/blist.h"
#include "../../protocol2/rabin/rabin.h"
#include "../../slist.h"
#include "../child.h"
#include "../manios.h"
#include "../resume.h"
#include "champ_chooser/champ_client.h"
#include "champ_chooser/champ_server.h"
#include "champ_chooser/hash.h"
#include "dpth.h"
#include "backup_phase2.h"

#define END_SIGS		0x01
#define END_BACKUP		0x02
#define END_REQUESTS		0x04
#define END_BLK_REQUESTS	0x08

#define BLKS_MAX_UNREQUESTED	BLKS_MAX_IN_MEM/4
// This needs to be greater than BLKS_MAX_UNREQUESTED
#define SLIST_MAX_IN_MEM	BLKS_MAX_IN_MEM

static int breaking=0;
static int breakcount=0;

static int data_needed(struct sbuf *sb)
{
	if(sb->path.cmd==CMD_FILE)
		return 1;
	if(sb->path.cmd==CMD_METADATA)
		return 1;
	return 0;
}

static int manio_component_to_chfd(struct asfd *chfd, char *path)
{
	struct iobuf wbuf;
	iobuf_from_str(&wbuf, CMD_MANIFEST, path);
	return chfd->write(chfd, &wbuf);
}

static int unchanged(struct sbuf *csb, struct sbuf *sb,
	struct manios *manios, struct asfd *chfd)
{
	int ret=-1;
	char *fpath=NULL;
	if(!(fpath=strdup_w(manios->changed->offset->fpath, __func__)))
		goto end;
	if(manio_copy_entry(csb, sb,
		manios->current, manios->unchanged,
		/*seed_src*/NULL, /*seed_dst*/NULL)<0)
			goto end;
	if(strcmp(fpath, manios->changed->offset->fpath))
	{
		// If the copy crossed a manio boundary, we should tell the
		// champ server to load the previous one as a candidate.
		if(manio_component_to_chfd(chfd, fpath))
			goto end;
	}
	ret=0;
end:
	free_w(&fpath);
	return ret;
}

// Return -1 for error, 0 for entry not changed, 1 for entry changed (or new).
static int found_in_current_manifest(struct sbuf *csb, struct sbuf *sb,
	struct manios *manios, struct asfd *chfd,
	struct cntr *cntr)
{
	// Located the entry in the current manifest.
	// If the file type changed, I think it is time to back it up again
	// (for example, EFS changing to normal file, or back again).
	if(csb->path.cmd!=sb->path.cmd)
	{
		if(manio_forward_through_sigs(csb, manios->current)<0)
			return -1;
		return 1;
	}

	// mtime is the actual file data.
	// ctime is the attributes or meta data.
	if(csb->statp.st_mtime==sb->statp.st_mtime
	  && csb->statp.st_ctime==sb->statp.st_ctime)
	{
		// Got an unchanged file.
		cntr_add_same(cntr, sb->path.cmd);
		return unchanged(csb, sb, manios, chfd);
	}

	if(csb->statp.st_mtime==sb->statp.st_mtime
	  && csb->statp.st_ctime!=sb->statp.st_ctime)
	{
		// FIX THIS:
		// File data stayed the same, but attributes or meta data
		// changed. We already have the attributes, but may need to
		// get extra meta data.
		cntr_add_same(cntr, sb->path.cmd);
		return unchanged(csb, sb, manios, chfd);
	}

	// File data changed.
	cntr_add_changed(cntr, sb->path.cmd);
	if(manio_forward_through_sigs(csb, manios->current)<0)
		return -1;
	return 1;
}

// Return -1 for error, 0 for entry not changed, 1 for entry changed (or new).
static int entry_changed(struct sbuf *sb,
	struct manios *manios, struct asfd *chfd, struct sbuf **csb,
	struct cntr *cntr)
{
	static int finished=0;
	int pcmp;

	if(finished)
	{
		cntr_add_new(cntr, sb->path.cmd);
		return 1;
	}

	if(*csb && (*csb)->path.buf)
	{
		// Already have an entry.
	}
	else
	{
		// Need to read another.
		switch(manio_read(manios->current, *csb))
		{
			case 1: // Reached the end.
				sbuf_free(csb);
				finished=1;
				cntr_add_new(cntr, sb->path.cmd);
				return 1;
			case -1: return -1;
		}
		if(!(*csb)->path.buf)
		{
			logp("Should have a path at this point, but do not, in %s\n", __func__);
			return -1;
		}
		// Got an entry.
	}

	while(1)
	{
		if(!(pcmp=sbuf_pathcmp(*csb, sb)))
			return found_in_current_manifest(*csb, sb,
					manios, chfd, cntr);
		else if(pcmp>0)
		{
			cntr_add_new(cntr, sb->path.cmd);
			return 1;
		}
//		cntr_add_deleted(cntr, (*csb)->path.cmd);
		// Behind - need to read more data from the old manifest.
		switch(manio_read(manios->current, *csb))
		{
			case 1: // Reached the end.
				sbuf_free(csb);
				cntr_add_new(cntr, sb->path.cmd);
				return 1;
			case -1: return -1;
		}
		// Got something, go back around the loop.
	}

	return 0;
}

static int add_data_to_store(struct cntr *cntr,
	struct slist *slist, struct iobuf *rbuf, struct dpth *dpth)
{
	static struct blk *blk=NULL;

	// Find the first one in the list that was requested.
	// FIX THIS: Going up the list here, and then later
	// when writing to the manifest is not efficient.
	for(blk=slist->blist->head;
		blk && (!blk->requested || blk->got==BLK_GOT); blk=blk->next)
	{
	//	logp("try: %d %d\n", blk->index, blk->got);
	}
	if(!blk)
	{
		logp("Received data but could not find next requested block.\n");
		if(!slist->blist->head)
			logp("and slist->blist->head is null\n");
		else
			logp("head index: %" PRIu64 "\n", slist->blist->head->index);
		return -1;
	}

// FIX THIS
#ifndef UTEST
	if(blk_verify(blk->fingerprint, blk->md5sum, rbuf->buf, rbuf->len)<=0)
	{
		logp("ERROR: Block %" PRIu64 " from client did not verify.\n",
			blk->index);
		return -1;
	}
#endif

	// Add it to the data store straight away.
	if(dpth_protocol2_fwrite(dpth, rbuf, blk)) return -1;

	cntr_add(cntr, CMD_DATA, 0);

	blk->got=BLK_GOT;
	blk=blk->next;

	return 0;
}

static int set_up_for_sig_info(struct slist *slist, struct iobuf *attr,
	uint64_t index)
{
	struct sbuf *sb;

	for(sb=slist->add_sigs_here; sb; sb=sb->next)
	{
		if(!sb->protocol2->index)
			continue;
		if(index==sb->protocol2->index)
			break;
	}
	if(!sb)
	{
		logp("Could not find %" PRIu64 " in request list\n", index);
		return -1;
	}
	// Replace the attribs with the more recent values.
	iobuf_free_content(&sb->attr);
	iobuf_move(&sb->attr, attr);

	// Mark the end of the previous file.
	slist->add_sigs_here->protocol2->bend=slist->blist->tail;

	slist->add_sigs_here=sb;

	// Incoming sigs now need to get added to 'add_sigs_here'
	return 0;
}

/*
static void dump_blks(const char *msg, struct blk *b)
{
	struct blk *xx;
	for(xx=b; xx; xx=xx->next)
		printf("%s: %d %d %p\n", msg, xx->index, xx->got, xx);
}
*/

static int add_to_sig_list(struct slist *slist, struct iobuf *rbuf)
{
	// Goes on slist->add_sigs_here
	struct blk *blk;
	struct protocol2 *protocol2;

	if(!(blk=blk_alloc())) return -1;
	blist_add_blk(slist->blist, blk);

	protocol2=slist->add_sigs_here->protocol2;
	if(!protocol2->bstart) protocol2->bstart=blk;
	if(!protocol2->bsighead) protocol2->bsighead=blk;

	if(blk_set_from_iobuf_sig(blk, rbuf)) return -1;

	// Need to send sigs to champ chooser, therefore need to point
	// to the oldest unsent one if nothing is pointed to yet.
	if(!slist->blist->blk_for_champ_chooser)
		slist->blist->blk_for_champ_chooser=blk;

	return 0;
}

static int deal_with_read(struct iobuf *rbuf, struct slist *slist,
	struct cntr *cntr, uint8_t *end_flags, struct dpth *dpth)
{
	int ret=0;
	static struct iobuf attr;
	static uint64_t index;

	switch(rbuf->cmd)
	{
		/* Incoming block data. */
		case CMD_DATA:
			if(add_data_to_store(cntr, slist, rbuf, dpth))
				goto error;
			goto end;

		/* Incoming block signatures. */
		case CMD_ATTRIBS_SIGS:

			iobuf_init(&attr);
			iobuf_move(&attr, rbuf);
			index=decode_file_no(&attr);

			// Need to go through slist to find the matching
			// entry.
			if(set_up_for_sig_info(slist, &attr, index))
				goto error;
			return 0;
		case CMD_SIG:
			if(add_to_sig_list(slist, rbuf))
				goto error;
			goto end;

		/* Incoming control/message stuff. */
		case CMD_MESSAGE:
		case CMD_WARNING:
		{
			log_recvd(rbuf, cntr, 0);
			goto end;
		}
		case CMD_GEN:
			if(!strcmp(rbuf->buf, "sigs_end"))
			{
				(*end_flags)|=END_SIGS;
				goto end;
			}
			else if(!strcmp(rbuf->buf, "backup_end"))
			{
				(*end_flags)|=END_BACKUP;
				goto end;
			}
			break;
		case CMD_INTERRUPT:
		{
			uint64_t file_no;
			file_no=base64_to_uint64(rbuf->buf);
			if(slist_del_sbuf_by_index(slist, file_no))
				goto error;
			goto end;
		}
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

static int get_wbuf_from_sigs(struct iobuf *wbuf, struct slist *slist,
	uint8_t *end_flags)
{
	static char req[32]="";
	struct sbuf *sb=slist->blks_to_request;

	while(sb && !(sb->flags & SBUF_NEED_DATA)) sb=sb->next;

	if(!sb)
	{
		slist->blks_to_request=NULL;
		if((*end_flags)&END_SIGS && !((*end_flags)&END_BLK_REQUESTS))
		{
			iobuf_from_str(wbuf,
				CMD_GEN, (char *)"blk_requests_end");
			(*end_flags)|=END_BLK_REQUESTS;
		}
		return 0;
	}
	if(!sb->protocol2->bsighead)
	{
		// Trying to move onto the next file.
		// ??? Does this really work?
		if(sb->protocol2->bend)
		{
			slist->blks_to_request=sb->next;
			printf("move to next\n");
		}
		if((*end_flags)&END_SIGS && !((*end_flags)&END_BLK_REQUESTS))
		{
			iobuf_from_str(wbuf,
				CMD_GEN, (char *)"blk_requests_end");
			(*end_flags)|=END_BLK_REQUESTS;
		}
		return 0;
	}

	if(sb->protocol2->bsighead->got==BLK_INCOMING)
		return 0;

	if(sb->protocol2->bsighead->got==BLK_NOT_GOT)
	{
		base64_from_uint64(sb->protocol2->bsighead->index, req);
		iobuf_from_str(wbuf, CMD_DATA_REQ, req);
		sb->protocol2->bsighead->requested=1;
	}

	// Move on.
	if(sb->protocol2->bsighead==sb->protocol2->bend)
	{
		slist->blks_to_request=sb->next;
		sb->protocol2->bsighead=sb->protocol2->bstart;
	}
	else
	{
		sb->protocol2->bsighead=sb->protocol2->bsighead->next;
	}
	return 0;
}

static void get_wbuf_from_files(struct iobuf *wbuf, struct slist *slist,
	struct manios *manios, uint8_t *end_flags, uint64_t *file_no)
{
	struct sbuf *sb=slist->last_requested;
	if(!sb)
	{
		if(!manios->phase1 && !((*end_flags)&END_REQUESTS))
		{
			iobuf_from_str(wbuf, CMD_GEN, (char *)"requests_end");
			(*end_flags)|=END_REQUESTS;
		}
		return;
	}

	if(sb->flags & SBUF_SENT_PATH || !(sb->flags & SBUF_NEED_DATA))
	{
		slist->last_requested=sb->next;
		return;
	}

	// Only need to request the path at this stage.
	iobuf_copy(wbuf, &sb->path);
	sb->flags |= SBUF_SENT_PATH;
	sb->protocol2->index=(*file_no)++;
}

static void get_wbuf_from_index(struct iobuf *wbuf, uint64_t index)
{
	static char *p;
	static char tmp[32];
	p=tmp;
	p+=to_base64(index, tmp);
	*p='\0';
	iobuf_from_str(wbuf, CMD_WRAP_UP, tmp);
}

static int write_endfile(struct sbuf *sb, struct manios *manios)
{
	struct iobuf endfile;

	if(sb->flags & SBUF_END_WRITTEN_TO_MANIFEST)
		return 0;
	if(!iobuf_is_filedata(&sb->path))
		return 0;

	sb->flags |= SBUF_END_WRITTEN_TO_MANIFEST;
	// FIX THIS: Should give a proper length and md5sum.
	iobuf_from_str(&endfile, CMD_END_FILE, (char *)"0:0");
	return iobuf_send_msg_fzp(&endfile, manios->changed->fzp);
}

static void blist_adjust_head(struct blist *blist, struct sbuf *sb)
{
	struct blk *b;
	while(blist->head!=sb->protocol2->bstart)
	{
		b=blist->head->next;
		if(blist->head==blist->blk_from_champ_chooser)
			blist->blk_from_champ_chooser=b;
		blk_free(&blist->head);
		blist->head=b;
	}
	if(!blist->head)
		blist->tail=NULL;
}

static int sbuf_needs_data(struct sbuf *sb, struct asfd *asfd,
	struct asfd *chfd, struct manios *manios,
	struct slist *slist, int end_flags)
{
	int ret=-1;
	struct blk *blk;
	static struct iobuf wbuf;
	struct blist *blist=slist->blist;
	static int unrequested=0;

	if(!(sb->flags & SBUF_HEADER_WRITTEN_TO_MANIFEST))
	{
		if(manio_write_sbuf(manios->changed, sb)) goto end;
		sb->flags |= SBUF_HEADER_WRITTEN_TO_MANIFEST;
	}

	while((blk=sb->protocol2->bstart)
		&& blk->got==BLK_GOT
		&& (blk->next || end_flags&END_BACKUP))
	{
		if(blk->got_save_path
		  && !blk_is_zero_length(blk))
		{
			if(breaking && breakcount--==0)
			{
				breakpoint(breaking, __func__);
				goto end;
			}
			if(manio_write_sig_and_path(manios->changed, blk))
				goto end;
			if(manios->changed->sig_count==0)
			{
				// Have finished a manifest file. Want to start
				// using it as a dedup candidate now.
				if(manio_component_to_chfd(chfd,
					manios->changed->offset->ppath))
						goto end;

				// The champ chooser has the candidate. Now,
				// empty our local hash table.
				hash_delete_all();
				// Add the most recent block, so identical
				// adjacent blocks are deduplicated well.
				if(hash_load_blk(blk))
					goto end;
			}
		}

		if(!blk->requested)
			unrequested++;

		if(unrequested>BLKS_MAX_UNREQUESTED)
		{
			unrequested=0;
			// Let the client know that it can free memory if there
			// was a long consecutive number of unrequested blocks.
			get_wbuf_from_index(&wbuf, blk->index);
			if(asfd->write(asfd, &wbuf))
				goto end;
		}

		if(blk==sb->protocol2->bend)
		{
			blist_adjust_head(blist, sb);
			if(write_endfile(sb, manios)) return -1;
			slist_advance(slist);
			return 1;
		}

		if(sb->protocol2->bsighead==sb->protocol2->bstart)
			sb->protocol2->bsighead=blk->next;
		sb->protocol2->bstart=blk->next;
		if(blk==blist->blk_from_champ_chooser)
			blist->blk_from_champ_chooser=blk->next;
	}
	if(!blk && sb && !sb->protocol2->bend && (end_flags&END_BACKUP))
	{
		// Write endfile for the very last file.
		if(write_endfile(sb, manios)) return -1;
	}
	ret=0;
end:
	blist_adjust_head(blist, sb);
	return ret;
}

static int write_to_changed_file(struct asfd *asfd,
	struct asfd *chfd, struct manios *manios,
	struct slist *slist, int end_flags)
{
	struct sbuf *sb;
	if(!slist) return 0;

	while((sb=slist->head))
	{
		if(sb->flags & SBUF_NEED_DATA)
		{
			switch(sbuf_needs_data(sb, asfd, chfd, manios, slist,
				end_flags))
			{
				case 0: return 0;
				case 1: continue;
				default: return -1;
			}

		}
		else
		{
			// No change, can go straight in.
			if(manio_write_sbuf(manios->changed, sb)) return -1;
			if(write_endfile(sb, manios)) return -1;

			// Move along.
			slist_advance(slist);
		}
	}
	return 0;
}

static int maybe_add_from_scan(struct manios *manios,
	struct slist *slist, struct asfd *chfd, struct sbuf **csb,
	struct cntr *cntr)
{
	int ret=-1;
	struct sbuf *snew=NULL;

	while(1)
	{
		sbuf_free(&snew);
		if(!manios->phase1) return 0;
		// Limit the amount loaded into memory at any one time.
		if(slist->count>SLIST_MAX_IN_MEM)
			return 0;
		if(!(snew=sbuf_alloc(PROTO_2))) goto end;

		switch(manio_read(manios->phase1, snew))
		{
			case 0: break;
			case 1: manio_close(&manios->phase1);
				ret=0; // Finished.
			default: goto end;
		}

		switch(entry_changed(snew, manios, chfd, csb, cntr))
		{
			case 0: continue; // No change.
			case 1: break;
			default: goto end; // Error.
		}

		if(data_needed(snew)) snew->flags|=SBUF_NEED_DATA;

		slist_add_sbuf(slist, snew);
		snew=NULL;
	}
	return 0;
end:
	sbuf_free(&snew);
	return ret;
}

static int append_for_champ_chooser(struct asfd *chfd,
	struct blist *blist, int end_flags)
{
	static int finished_sending=0;
	static struct iobuf wbuf;
	static struct blk *blk=NULL;

	while(blist->blk_for_champ_chooser)
	{
		blk=blist->blk_for_champ_chooser;
		// If we send too many blocks to the champ chooser at once,
		// it can go faster than we can send paths to completed
		// manifests to it. This means that deduplication efficiency
		// is reduced (although speed may be faster).
		// So limit the sending.
		if(blk->index
		  - blist->head->index > MANIFEST_SIG_MAX)
			return 0;

		blk_to_iobuf_sig(blk, &wbuf);

		switch(chfd->append_all_to_write_buffer(chfd, &wbuf))
		{
			case APPEND_OK: break;
			case APPEND_BLOCKED:
				return 0; // Try again later.
			default: return -1;
		}
		blist->blk_for_champ_chooser=blk->next;
	}
	if(end_flags&END_SIGS
	  && !finished_sending && !blist->blk_for_champ_chooser)
	{
		iobuf_from_str(&wbuf, CMD_GEN, (char *)"sigs_end");
		switch(chfd->append_all_to_write_buffer(chfd, &wbuf))
		{
			case APPEND_OK: break;
			case APPEND_BLOCKED:
				return 0; // Try again later.
			default: return -1;
		}
		finished_sending++;
	}
	return 0;
}

static int mark_not_got(struct blk *blk, struct dpth *dpth)
{
	const char *path;

	if(blk->got!=BLK_INCOMING) return 0;
	blk->got=BLK_NOT_GOT;

	// Need to get the data for this blk from the client.
	// Set up the details of where it will be saved.
	if(!(path=dpth_protocol2_mk(dpth))) return -1;

	// FIX THIS: make dpth give us the path in a uint8 array.
	blk->savepath=savepathstr_with_sig_to_uint64(path);
	blk->got_save_path=1;
	// Load it into our local hash table.
	if(hash_load_blk(blk))
		return -1;
	if(dpth_protocol2_incr_sig(dpth))
		return -1;
	return 0;
}

static struct hash_strong *in_local_hash(struct blk *blk)
{
	static struct hash_weak *hash_weak;

	if(!(hash_weak=hash_weak_find(blk->fingerprint)))
		return NULL;
	return hash_strong_find(hash_weak, blk->md5sum);
}

static int simple_deduplicate_blk(struct blk *blk)
{
	static struct hash_strong *hash_strong;
	if(blk->got!=BLK_INCOMING)
		return 0;
	if((hash_strong=in_local_hash(blk)))
	{
		blk->savepath=hash_strong->savepath;
		blk->got_save_path=1;
		blk->got=BLK_GOT;
		return 1;
	}
	return 0;
}

static int mark_up_to_index(struct blist *blist,
	uint64_t index, struct dpth *dpth)
{
	struct blk *blk;

	// Mark everything that was not got, up to the given index.
	for(blk=blist->blk_from_champ_chooser;
	  blk && blk->index!=index; blk=blk->next)
	{
		if(simple_deduplicate_blk(blk))
			continue;
		if(mark_not_got(blk, dpth))
			return -1;
	}
	if(!blk)
	{
		logp("Could not find index from champ chooser: %" PRIu64 "\n",
			index);
		return -1;
	}
	simple_deduplicate_blk(blk);

//logp("Found index from champ chooser: %lu\n", index);
//printf("index from cc: %d\n", index);
	blist->blk_from_champ_chooser=blk;
	return 0;
}

static int deal_with_sig_from_chfd(struct iobuf *rbuf, struct blist *blist,
	struct dpth *dpth)
{
	static struct blk b;
	if(blk_set_from_iobuf_index_and_savepath(&b, rbuf))
		return -1;

	if(mark_up_to_index(blist, b.index, dpth))
		return -1;
	blist->blk_from_champ_chooser->savepath=b.savepath;
	blist->blk_from_champ_chooser->got=BLK_GOT;
	blist->blk_from_champ_chooser->got_save_path=1;
	return 0;
}

static int deal_with_wrap_up_from_chfd(struct iobuf *rbuf, struct blist *blist,
	struct dpth *dpth)
{
	static struct blk b;
	if(blk_set_from_iobuf_wrap_up(&b, rbuf))
		return -1;

	if(mark_up_to_index(blist, b.index, dpth)) return -1;
	if(mark_not_got(blist->blk_from_champ_chooser, dpth)) return -1;
	return 0;
}

static int deal_with_read_from_chfd(struct asfd *chfd,
	struct blist *blist, struct dpth *dpth, struct cntr *cntr)
{
	int ret=-1;

	// Deal with champ chooser read here.
	//printf("read from cc: %s\n", chfd->rbuf->buf);
	switch(chfd->rbuf->cmd)
	{
		case CMD_SIG:
			// Get these for blks that the champ chooser has found.
			if(deal_with_sig_from_chfd(chfd->rbuf, blist, dpth))
				goto end;
			cntr_add_same(cntr, CMD_DATA);
			break;
		case CMD_WRAP_UP:
			if(deal_with_wrap_up_from_chfd(chfd->rbuf, blist, dpth))
				goto end;
			break;
		default:
			iobuf_log_unexpected(chfd->rbuf, __func__);
			goto end;
	}
	ret=0;
end:
	iobuf_free_content(chfd->rbuf);
	return ret;
}

static int check_for_missing_work_in_slist(struct slist *slist)
{
	struct sbuf *sb=NULL;

	if(slist->blist->head)
	{
		logp("ERROR: finishing but still want block: %" PRIu64 "\n",
			slist->blist->head->index);
		return -1;
	}

	for(sb=slist->head; sb; sb=sb->next)
	{
		if(!(sb->flags & SBUF_END_WRITTEN_TO_MANIFEST))
		{
			logp("ERROR: finishing but still waiting for: %s\n",
				iobuf_to_printable(&slist->head->path));
			return -1;
		}
	}
	return 0;
}

#ifndef UTEST
static
#endif
int do_backup_phase2_server_protocol2(struct async *as, struct asfd *chfd,
	struct sdirs *sdirs, int resume, struct conf **confs)
{
	int ret=-1;
	uint8_t end_flags=0;
	struct slist *slist=NULL;
	struct iobuf wbuf;
	struct dpth *dpth=NULL;
	man_off_t *p1pos=NULL;
	struct manios *manios=NULL;
	// This is used to tell the client that a number of consecutive blocks
	// have been found and can be freed.
	struct asfd *asfd=NULL;
	struct cntr *cntr=NULL;
	struct sbuf *csb=NULL;
	uint64_t file_no=1;
	int fail_on_warning=0;
	struct cntr_ent *warn_ent=NULL;

	if(!as)
	{
		logp("async not provided to %s()\n", __func__);
		goto end;
	}
	if(!sdirs)
	{
		logp("sdirs not provided to %s()\n", __func__);
		goto end;
	}
	if(!confs)
	{
		logp("confs not provided to %s()\n", __func__);
		goto end;
	}
	asfd=as->asfd;
	if(!asfd)
	{
		logp("asfd not provided to %s()\n", __func__);
		goto end;
	}
	if(!chfd)
	{
		logp("chfd not provided to %s()\n", __func__);
		goto end;
	}
	cntr=get_cntr(confs);
	fail_on_warning=get_int(confs[OPT_FAIL_ON_WARNING]);
	if(cntr)
		warn_ent=cntr->ent[CMD_WARNING];

	if(get_int(confs[OPT_BREAKPOINT])>=2000
	  && get_int(confs[OPT_BREAKPOINT])<3000)
	{
		breaking=get_int(confs[OPT_BREAKPOINT]);
		breakcount=breaking-2000;
	}

	blks_generate_init();

	logp("Phase 2 begin (recv backup data)\n");

	if(!(dpth=dpth_alloc())
	  || dpth_protocol2_init(dpth,
		sdirs->data,
		get_string(confs[OPT_CNAME]),
		sdirs->cfiles,
		get_int(confs[OPT_MAX_STORAGE_SUBDIRS])))
			goto end;
	if(resume)
	{
		if(!(p1pos=do_resume(sdirs, dpth, confs)))
			goto end;
		if(cntr_send_sdirs(asfd, sdirs, confs, CNTR_STATUS_BACKUP))
			goto end;
	}

	if(!(manios=manios_open_phase2(sdirs, p1pos, PROTO_2))
	  || !(slist=slist_alloc())
	  || !(csb=sbuf_alloc(PROTO_2)))
		goto end;

	iobuf_free_content(asfd->rbuf);

	memset(&wbuf, 0, sizeof(struct iobuf));
	while(!(end_flags&END_BACKUP))
	{
		if(check_fail_on_warning(fail_on_warning, warn_ent))
			goto end;

		if(write_status(CNTR_STATUS_BACKUP,
			csb && csb->path.buf?csb->path.buf:"", cntr))
				goto end;

		if(maybe_add_from_scan(manios, slist, chfd, &csb, cntr))
			goto end;

		if(!wbuf.len)
		{
			if(get_wbuf_from_sigs(&wbuf, slist, &end_flags))
				goto end;
			if(!wbuf.len)
			{
				get_wbuf_from_files(&wbuf, slist,
					manios, &end_flags, &file_no);
			}
		}

		if(wbuf.len
		 && asfd->append_all_to_write_buffer(asfd, &wbuf)==APPEND_ERROR)
			goto end;

		if(append_for_champ_chooser(chfd, slist->blist, end_flags))
			goto end;

		if(as->read_write(as))
		{
			logp("error from as->read_write in %s\n", __func__);
			goto end;
		}

		while(asfd->rbuf->buf)
		{
			if(deal_with_read(asfd->rbuf, slist, cntr,
				&end_flags, dpth))
					goto end;
			// Get as much out of the readbuf as possible.
			if(asfd->parse_readbuf(asfd))
				goto end;
		}
		while(chfd->rbuf->buf)
		{
			if(deal_with_read_from_chfd(chfd,
				slist->blist, dpth, cntr))
					goto end;
			// Get as much out of the readbuf as possible.
			if(chfd->parse_readbuf(chfd))
				goto end;
		}

		if(write_to_changed_file(asfd, chfd, manios,
			slist, end_flags))
				goto end;
	}

	// Hack: If there are some entries left after the last entry that
	// contains block data, it will not be written to the changed file
	// yet because the last entry of block data has not had
	// sb->protocol2->bend set.
	if(slist->head && slist->head->next)
	{
		struct sbuf *sb=NULL;
		sb=slist->head;
		slist->head=sb->next;
		sbuf_free(&sb);
		if(write_to_changed_file(asfd, chfd, manios,
			slist, end_flags))
				goto end;
	}

	if(manios_close(&manios))
		goto end;

	if(check_for_missing_work_in_slist(slist))
		goto end;

	// Need to release the last left. There should be one at most.
	if(dpth->head && dpth->head->next)
	{
		logp("ERROR: More data locks remaining after: %s\n",
			dpth->head->save_path);
		goto end;
	}
	if(dpth_release_all(dpth)) goto end;

	if(check_fail_on_warning(fail_on_warning, warn_ent))
		goto end;

	ret=0;
end:
	if(ret)
	{
		if(slist && slist->head)
			logp("  last tried file: %s\n",
				iobuf_to_printable(&slist->head->path));
	}
	logp("End backup\n");
	sbuf_free(&csb);
	slist_free(&slist);
	if(asfd) iobuf_free_content(asfd->rbuf);
	if(chfd) iobuf_free_content(chfd->rbuf);
	dpth_free(&dpth);
	manios_close(&manios);
	man_off_t_free(&p1pos);
	blks_generate_free();
	hash_delete_all();
	return ret;
}

int backup_phase2_server_protocol2(struct async *as, struct sdirs *sdirs,
	int resume, struct conf **confs)
{
	int ret=-1;
	struct asfd *chfd=NULL;
	if(!(chfd=champ_chooser_connect(as, sdirs, confs, resume)))
	{
		logp("problem connecting to champ chooser\n");
		goto end;
	}
	ret=do_backup_phase2_server_protocol2(as, chfd, sdirs, resume, confs);
end:
	if(chfd) as->asfd_remove(as, chfd);
	asfd_free(&chfd);
	return ret;
}
