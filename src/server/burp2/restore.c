#include "include.h"
#include "champ_chooser/hash.h"
#include "../../burp2/slist.h"
#include "../../server/bu.h"
#include "../../server/burp1/restore.h"
#include "../../server/manio.h"
#include "../../server/monitor/status_client.h"
#include "../../server/sdirs.h"

static int restore_sbuf(struct asfd *asfd, struct sbuf *sb, enum action act,
	enum cstat_status status, struct conf *conf, int *need_data)
{
	//logp("%s: %s\n", act==ACTION_RESTORE?"restore":"verify", sb->path.buf);
	if(write_status(status, sb->path.buf, conf)) return -1;

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

static int restore_ent(struct asfd *asfd,
	struct sbuf **sb,
	struct slist *slist,
	enum action act,
	enum cstat_status status,
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
	//printf("want to restore: %s\n", (*sb)->path);

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
//printf("do dir: %s\n", xb->path.buf);
			// Can now restore because nothing else is
			// fiddling in a subdirectory.
			if(restore_sbuf(asfd, xb, act, status,
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
//printf("add to head: %s\n", (*sb)->path.buf);
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
		if(restore_sbuf(asfd, *sb, act, status, conf, need_data))
			goto end;
	}
	ret=0;
end:
	return ret;
}

static int restore_remaining_dirs(struct asfd *asfd,
	struct slist *slist, enum action act,
	enum cstat_status status, struct conf *conf, int *need_data)
{
	struct sbuf *sb;
	// Restore any directories that are left in the list.
	for(sb=slist->head; sb; sb=sb->next)
	{
//printf("remaining dir: %s\n", sb->path.buf);
		if(restore_sbuf(asfd, sb, act, status, conf, need_data))
			return -1;
	}
	return 0;
}

/* This function reads the manifest to determine whether it may be more
   efficient to just copy the data files across and unpack them on the other
   side. If it thinks it is, it will then do it.
   Return -1 on error, 1 if it copied the data across, 0 if it did not. */
static int maybe_copy_data_files_across(struct asfd *asfd,
	const char *manifest,
	const char *datadir, int srestore, regex_t *regex, struct conf *conf,
	struct slist *slist,
	enum action act, enum cstat_status status)
{
	int ars;
	int ret=-1;
	struct sbuf *sb=NULL;
	struct blk *blk=NULL;
	struct manio *manio=NULL;
	uint64_t blkcount=0;
	uint64_t datcount=0;
	struct hash_weak *tmpw;
	struct hash_weak *hash_weak;
	uint64_t estimate_blks;
	uint64_t estimate_dats;
	uint64_t estimate_one_dat;
	int need_data=0;
	int last_ent_was_dir=0;
	char sig[128]="";

	// If the client has no restore_spool directory, we have to fall back
	// to the stream style restore.
	if(!conf->restore_spool) return 0;
	
	if(!(manio=manio_alloc())
	  || manio_init_read(manio, manifest)
	  || !(sb=sbuf_alloc(conf))
	  || !(blk=blk_alloc()))
		goto end;

	while(1)
	{
		if((ars=manio_sbuf_fill(manio, asfd, sb, blk, NULL, conf))<0)
		{
			logp("Error from manio_sbuf_fill() in %s\n",
				__func__);
			goto end; // Error;
		}
		else if(ars>0)
			break; // Finished OK.
		if(!blk->got_save_path)
		{
			sbuf_free_content(sb);
			continue;
		}

		if((!srestore || check_srestore(conf, sb->path.buf))
		  && check_regex(regex, sb->path.buf))
		{
			blkcount++;
			if(!hash_weak_find((uint64_t)blk->savepath))
			{
				if(!hash_weak_add((uint64_t)blk->savepath))
					goto end;
				datcount++;
			}
		}

		sbuf_free_content(sb);
	}

	estimate_blks=blkcount*RABIN_AVG;
	estimate_one_dat=DATA_FILE_SIG_MAX*RABIN_AVG;
	estimate_dats=datcount*estimate_one_dat;
	printf("%lu blocks = %lu bytes in stream approx\n",
		blkcount, estimate_blks);
	printf("%lu data files = %lu bytes approx\n",
		datcount, estimate_dats);

	if(estimate_blks < estimate_one_dat)
	{
		printf("Stream is less than the size of a data file.\n");
		printf("Use restore stream\n");
		return 0;
	}
	else if(estimate_dats >= 90*(estimate_blks/100))
	{
		printf("Stream is more than 90%% size of data files.\n");
		printf("Use restore stream\n");
		return 0;
	}
	else
	{
		printf("Data files are less than 90%% size of stream.\n");
		printf("Use data files\n");
	}

	printf("Client is using restore_spool: %s\n", conf->restore_spool);

	if(asfd->write_str(asfd, CMD_GEN, "restore_spool")
	  || asfd->read_expect(asfd, CMD_GEN, "restore_spool_ok"))
		goto end;

	// Send each of the data files that we found to the client.
	HASH_ITER(hh, hash_table, hash_weak, tmpw)
	{
		char msg[32];
		char path[32];
		char *fdatpath=NULL;
		snprintf(path, sizeof(path), "%014lX", hash_weak->weak);
		path[4]='/';
		path[9]='/';
		snprintf(msg, sizeof(msg), "dat=%s", path);
		printf("got: %s\n", msg);
		if(asfd->write_str(asfd, CMD_GEN, msg)) goto end;
		if(!(fdatpath=prepend_s(datadir, path)))
			goto end;
		if(send_a_file(asfd, fdatpath, conf))
		{
			free(fdatpath);
			goto end;
		}
		free(fdatpath);
	}

	if(asfd->write_str(asfd, CMD_GEN, "datfilesend")
	  || asfd->read_expect(asfd, CMD_GEN, "datfilesend_ok"))
		goto end;

	// Send the manifest to the client.
	if(manio_init_read(manio, manifest))
		goto end;
	blk->got_save_path=0;
	while(1)
	{
		if((ars=manio_sbuf_fill(manio, asfd, sb, blk, NULL, conf))<0)
		{
			logp("Error from manio_sbuf_fill() in %s\n",
				__func__);
			goto end; // Error;
		}
		else if(ars>0)
			break; // Finished OK.

		if(blk->got_save_path)
		{
			//if(async_write(asfd, CMD_DATA, blk->data, blk->length))
			//	return -1;
			// FIX THIS: Need to send this stuff unconverted.
			snprintf(sig, sizeof(sig),
#ifdef HAVE_WIN32
				"%016I64X%s%s",
#else
				"%016lX%s%s",
#endif
				blk->fingerprint,
				bytes_to_md5str(blk->md5sum),
				bytes_to_savepathstr_with_sig(blk->savepath));
			if(asfd->write_str(asfd, CMD_SIG, sig))
				goto end;
			blk->got_save_path=0;
			continue;
		}

		need_data=0;

		if((!srestore || check_srestore(conf, sb->path.buf))
		  && check_regex(regex, sb->path.buf))
		{
			if(restore_ent(asfd, &sb, slist, act, status, conf,
				&need_data, &last_ent_was_dir))
					goto end;
		}

		sbuf_free_content(sb);
	}

	ret=1;
end:
	blk_free(&blk);
	sbuf_free(&sb);
	manio_free(&manio);
	hash_delete_all();
	return ret;
}

static int restore_stream(struct asfd *asfd,
	const char *datadir, struct slist *slist,
	struct bu *bu, const char *manifest, regex_t *regex,
	int srestore, struct conf *conf, enum action act,
	enum cstat_status status)
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
	  || !(dpth=dpth_alloc(datadir)))
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
				continue;
			}
			else
			{
				char msg[256]="";
				snprintf(msg, sizeof(msg),
				  "Unexpected signature in manifest: "
#ifdef HAVE_WIN32
				  "%016I64X%s%s",
#else
				  "%016lX%s%s",
#endif
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
			if(restore_ent(asfd, &sb, slist, act, status, conf,
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

int restore_burp2(struct asfd *asfd, struct bu *bu, const char *manifest,
	regex_t *regex, int srestore, enum action act, struct sdirs *sdirs,
	enum cstat_status status, struct conf *conf)
{
	//int s=0;
	//size_t len=0;
	// For out-of-sequence directory restoring so that the
	// timestamps come out right:
	// FIX THIS!
//	int scount=0;
	struct slist *slist=NULL;
	int ret=-1;
	int ars=0;
	int need_data=0;

	if(!(slist=slist_alloc()))
		goto end;

	if(!(ars=maybe_copy_data_files_across(asfd, manifest, sdirs->data,
		srestore, regex, conf,
		slist, act, status)))
	{
		// Instead of copying all the blocks across, do it as a stream,
		// in the style of burp-1.x.x.
		if(restore_stream(asfd, sdirs->data, slist,
			bu, manifest, regex,
			srestore, conf, act, status)) 
				goto end;
	}
	else if(ars<0) goto end; // Error.

	// Restore has nearly completed OK.

	if(restore_remaining_dirs(asfd, slist, act, status, conf, &need_data))
		goto end;

	ret=restore_end(asfd, conf);

	cntr_print_end(conf->cntr);
	cntr_print(conf->cntr, act);

	ret=0;
end:
	slist_free(&slist);
	return ret;
}
