#include "../../burp.h"
#include "../../action.h"
#include "../../asfd.h"
#include "../../async.h"
#include "../../cmd.h"
#include "../../cntr.h"
#include "../../hexmap.h"
#include "../../log.h"
#include "../../prepend.h"
#include "../../protocol2/blk.h"
#include "../../regexp.h"
#include "../../server/protocol1/restore.h"
#include "../../slist.h"
#include "../manio.h"
#include "../restore.h"
#include "../sdirs.h"
#include "champ_chooser/hash.h"
#include "restore.h"

static int send_data(struct asfd *asfd, struct blk *blk,
	enum action act, struct sbuf *need_data, struct cntr *cntr)
{
	struct iobuf wbuf;

	switch(act)
	{
		case ACTION_RESTORE:
			iobuf_set(&wbuf, CMD_DATA, blk->data, blk->length);
			if(asfd->write(asfd, &wbuf)) return -1;
			return 0;
		case ACTION_VERIFY:
			// Need to check that the block has the correct
			// checksums.
			switch(blk_verify(blk->fingerprint, blk->md5sum,
				blk->data, blk->length))
			{
				case 1:
					iobuf_set(&wbuf, CMD_DATA, (char *)"0", 1);
					if(asfd->write(asfd, &wbuf)) return -1;
					cntr_add(cntr, CMD_DATA, 0);
					break; // All OK.
				case 0:
				{
					logw(asfd, cntr, "Checksum mismatch in block for %s:%s\n", iobuf_to_printable(&need_data->path), uint64_to_savepathstr_with_sig(blk->savepath));
					break;
		
				}
				default:
				{
					char msg[256];
					snprintf(msg, sizeof(msg), "Error when attempting to verify block for %s:%s\n", iobuf_to_printable(&need_data->path), uint64_to_savepathstr_with_sig(blk->savepath));
					return -1;
				}
			}
			return 0;
		default:
			logp("unknown action in %s: %d\n", __func__, act);
			return -1;
	}
}

int restore_sbuf_protocol2(struct asfd *asfd, struct sbuf *sb, enum action act,
	struct cntr *cntr, struct sbuf *need_data)
{
	if(asfd->write(asfd, &sb->attr)
	  || asfd->write(asfd, &sb->path))
		return -1;
	if(sbuf_is_link(sb)
	  && asfd->write(asfd, &sb->link))
		return -1;

	if(sb->protocol2->bstart)
	{
		// This will restore directory data on Windows.
		struct blk *b=NULL;
		struct blk *n=NULL;
		b=sb->protocol2->bstart;
		while(b)
		{
			if(send_data(asfd, b, act, need_data, cntr))
				return -1;
			n=b->next;
			blk_free(&b);
			b=n;
		}
		sb->protocol2->bstart=sb->protocol2->bend=NULL;
	}

	if(sbuf_is_filedata(sb))
	{
		if(need_data)
		{
			iobuf_copy(&need_data->path, &sb->path);
			sb->path.buf=NULL;
		}
	}
	else
		cntr_add(cntr, sb->path.cmd, 0);
	return 0;
}

int protocol2_extra_restore_stream_bits(struct asfd *asfd, struct blk *blk,
	struct slist *slist, enum action act,
	struct sbuf *need_data, int last_ent_was_dir, struct cntr *cntr)
{
	int ret=-1;
	if(need_data->path.buf)
	{
		ret=send_data(asfd, blk, act, need_data, cntr);
	}
	else if(last_ent_was_dir)
	{
		// Careful, blk is not allocating blk->data and the data there
		// can get changed if we try to keep it for later. So, need to
		// allocate new space and copy the bytes.
		struct blk *nblk;
		struct sbuf *xb;
		if(!(nblk=blk_alloc_with_data(blk->length)))
			goto end;
		nblk->length=blk->length;
		memcpy(nblk->data, blk->data, blk->length);
		xb=slist->head;
		if(!xb->protocol2->bstart)
			xb->protocol2->bstart=xb->protocol2->bend=nblk;
		else
		{
			xb->protocol2->bend->next=nblk;
			xb->protocol2->bend=nblk;
		}
		ret=0;
	}
	else
	{
		logw(asfd, cntr,
			"Unexpected signature in manifest: %016" PRIX64 "%s%s\n",
			blk->fingerprint,
			bytes_to_md5str(blk->md5sum),
			uint64_to_savepathstr_with_sig(blk->savepath));
	}
end:
	blk->data=NULL;
	return ret;
}
