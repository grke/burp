#include "include.h"
#include "../../cmd.h"
#include "champ_chooser/hash.h"
#include "../../slist.h"
#include "../../hexmap.h"
#include "../../server/burp1/restore.h"
#include "../manio.h"
#include "../sdirs.h"

int restore_sbuf_burp2(struct asfd *asfd, struct sbuf *sb, enum action act,
	enum cntr_status cntr_status, struct conf *conf, int *need_data)
{
	if(asfd->write(asfd, &sb->attr)
	  || asfd->write(asfd, &sb->path))
		return -1;
	if(sbuf_is_link(sb)
	  && asfd->write(asfd, &sb->link))
		return -1;

	if(sb->burp2->bstart)
	{
		// This will restore directory data on Windows.
		struct blk *b=NULL;
		struct blk *n=NULL;
		b=sb->burp2->bstart;
		while(b)
		{
			struct iobuf wbuf;
			iobuf_set(&wbuf, CMD_DATA, b->data, b->length);
			if(asfd->write(asfd, &wbuf)) return -1;
			n=b->next;
			blk_free(&b);
			b=n;
		}
		sb->burp2->bstart=sb->burp2->bend=NULL;
	}

	switch(sb->path.cmd)
	{
		case CMD_FILE:
		case CMD_ENC_FILE:
		case CMD_METADATA:
		case CMD_ENC_METADATA:
		case CMD_EFS_FILE:
			*need_data=1;
			return 0;
		default:
			cntr_add(conf->cntr, sb->path.cmd, 0);
			return 0;
	}
}

int burp2_extra_restore_stream_bits(struct asfd *asfd, struct blk *blk,
	struct slist *slist, int need_data, int last_ent_was_dir,
	struct conf *cconf)
{
	if(need_data)
	{
		struct iobuf wbuf;
		iobuf_set(&wbuf, CMD_DATA, blk->data, blk->length);
		if(asfd->write(asfd, &wbuf)) return -1;
	}
	else if(last_ent_was_dir)
	{
		// Careful, blk is not allocating blk->data and the data there
		// can get changed if we try to keep it for later. So, need to
		// allocate new space and copy the bytes.
		struct blk *nblk;
		struct sbuf *xb;
		if(!(nblk=blk_alloc_with_data(blk->length)))
			return -1;
		nblk->length=blk->length;
		memcpy(nblk->data, blk->data, blk->length);
		xb=slist->head;
		if(!xb->burp2->bstart)
			xb->burp2->bstart=xb->burp2->bend=nblk;
		else
		{
			xb->burp2->bend->next=nblk;
			xb->burp2->bend=nblk;
		}
	}
	else
	{
		char msg[256]="";
		snprintf(msg, sizeof(msg),
			"Unexpected signature in manifest: %016"PRIX64 "%s%s",
			blk->fingerprint,
			bytes_to_md5str(blk->md5sum),
			bytes_to_savepathstr_with_sig(blk->savepath));
		logw(asfd, cconf, msg);
	}
	blk->data=NULL;
	return 0;
}
