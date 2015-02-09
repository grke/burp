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

int restore_ent_burp2(struct asfd *asfd,
	struct sbuf **sb,
	struct slist *slist,
	enum action act,
	enum cntr_status cntr_status,
	struct conf *conf,
	int *need_data,
	int *last_ent_was_dir)
{
	int ret=-1;
	struct sbuf *xb;

	if(!(*sb)->path.buf)
	{
		logp("Got NULL path!\n");
		return -1;
	}
	//printf("want to restore: %s\n", (*sb)->path.buf);

	// Check if we have any directories waiting to be restored.
	while((xb=slist->head))
	{
		if(is_subdir(xb->path.buf, (*sb)->path.buf))
		{
			// We are still in a subdir.
			break;
		}
		else
		{
			// Can now restore because nothing else is
			// fiddling in a subdirectory.
			if(restore_sbuf_burp2(asfd, xb, act, cntr_status,
				conf, need_data)) goto end;
			slist->head=xb->next;
			sbuf_free(&xb);
		}
	}

	// If it is a directory, need to remember it and restore it later, so
	// that the permissions come out right.
	// Meta data of directories will also have the stat stuff set to be a
	// directory, so will also come out at the end.
	// FIX THIS: for Windows, need to read and remember the blocks that
	// go with the directories. Probably have to do the same for metadata
	// that goes with directories.
	if(S_ISDIR((*sb)->statp.st_mode))
	{
		// Add to the head of the list instead of the tail.
		(*sb)->next=slist->head;
		slist->head=*sb;

		*last_ent_was_dir=1;

		// Allocate a new sb.
		if(!(*sb=sbuf_alloc(conf))) goto end;
	}
	else
	{
		*last_ent_was_dir=0;
		if(restore_sbuf_burp2(asfd, *sb, act,
			cntr_status, conf, need_data)) goto end;
	}
	ret=0;
end:
	return ret;
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
		if(buf)
		{
			//logp("got read quick\n");
			if(cmd==CMD_WARNING)
			{
				logp("WARNING: %s\n", buf);
				cntr_add(conf->cntr, cmd, 0);
				free(buf); buf=NULL;
				continue;
			}
			else if(cmd==CMD_INTERRUPT)
			{
				// Client wanted to interrupt the
				// sending of a file. But if we are
				// here, we have already moved on.
				// Ignore.
				free(buf); buf=NULL;
				continue;
			}
			else
			{
				logp("unexpected cmd from client: %c:%s\n", cmd, buf);
				free(buf); buf=NULL;
				goto end;
			}
		}
*/

		if((ars=manio_sbuf_fill(manio, asfd, sb, blk, dpth, conf))<0)
		{
			logp("Error from manio_sbuf_fill() in %s\n", __func__);
			goto end; // Error;
		}
		else if(ars>0)
			break; // Finished OK.

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
		  && check_regex(regex, sb->path.buf))
		{
			if(restore_ent_burp2(asfd, &sb, slist, act,
				cntr_status, conf,
				&need_data, &last_ent_was_dir))
					goto end;
		}

		sbuf_free_content(sb);
	}

	ret=0;
end:
	blk_free(&blk);
	sbuf_free(&sb);
	manio_free(&manio);
	dpth_free(&dpth);
	return ret;
}
