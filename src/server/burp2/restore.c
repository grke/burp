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
	//logp("%s: %s\n", act==ACTION_RESTORE?"restore":"verify", sb->path.buf);
	if(write_status(cntr_status, sb->path.buf, conf)) return -1;

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

int restore_stream_burp2(struct asfd *asfd,
	struct sdirs *sdirs, struct slist *slist,
	struct bu *bu, const char *manifest, regex_t *regex,
	int srestore, struct conf *conf, enum action act,
	enum cntr_status cntr_status)
{
	int ars;
	int ret=-1;
	int need_data=0;
	int last_ent_was_dir=0;
	struct sbuf *sb=NULL;
	struct blk *blk=NULL;
	struct dpth *dpth=NULL;
	struct manio *manio=NULL;
	struct iobuf wbuf;

	if(asfd->write_str(asfd, CMD_GEN, "restore_stream")
	  || asfd->read_expect(asfd, CMD_GEN, "restore_stream_ok"))
		goto end;

	if(!(manio=manio_alloc())
	  || manio_init_read(manio, manifest)
	  || !(sb=sbuf_alloc(conf))
	  || !(blk=blk_alloc())
	  || !(dpth=dpth_alloc(sdirs->data)))
		goto end;

	while(1)
	{
/* FIX THIS to allow the client to interrupt the flow for a file.
		char *buf=NULL;
		if(async_read_quick(&cmd, &buf, &len))
		{
			logp("read quick error\n");
			goto end;
		}
		if(buf) switch(cmd)
		{
			case CMD_WARNING:
				logp("WARNING: %s\n", buf);
				cntr_add(conf->cntr, cmd, 0);
				free_w(&buf);
				continue;
			case CMD_INTERRUPT:
				// Client wanted to interrupt the
				// sending of a file. But if we are
				// here, we have already moved on.
				// Ignore.
				free_w(&buf);
				continue;
			default:
				logp("unexpected cmd from client: %c:%s\n", cmd, buf);
				free_w(&buf);
				goto end;
		}
*/

		switch(manio_sbuf_fill(manio, asfd, sb, blk, dpth, conf))
		{
			case 0: break; // Keep going.
			case 1: ret=0; goto end; // Finished OK.
			default: goto end; // Error;
		}

		if(blk->data)
		{
			if(need_data)
			{
				iobuf_set(&wbuf,
					CMD_DATA, blk->data, blk->length);
				if(asfd->write(asfd, &wbuf)) return -1;
			}
			else if(last_ent_was_dir)
			{
				// Careful, blk is not allocating blk->data
				// and the data there can get changed if we
				// try to keep it for later. So, need to
				// allocate new space and copy the bytes.
				struct blk *nblk;
				struct sbuf *xb;
	  			if(!(nblk=blk_alloc_with_data(blk->length)))
					goto end;
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
				//continue;
			}
			else
			{
				char msg[256]="";
				snprintf(msg, sizeof(msg),
				  "Unexpected signature in manifest: "
				  "%016"PRIX64 "%s%s",
					blk->fingerprint,
					bytes_to_md5str(blk->md5sum),
					bytes_to_savepathstr_with_sig(
						blk->savepath));
				logw(asfd, conf, msg);
			}
			blk->data=NULL;
			continue;
		}

		need_data=0;

		if((!srestore || check_srestore(conf, sb->path.buf))
		  && check_regex(regex, sb->path.buf)
		  && restore_ent(asfd, &sb, slist,
			bu, act, sdirs, cntr_status, conf,
			&need_data, &last_ent_was_dir))
				goto end;

		sbuf_free_content(sb);
	}

end:
	blk_free(&blk);
	sbuf_free(&sb);
	manio_free(&manio);
	dpth_free(&dpth);
	return ret;
}
