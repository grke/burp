#include "../../burp.h"
#include "../../action.h"
#include "../../asfd.h"
#include "../../async.h"
#include "../../cmd.h"
#include "../../cntr.h"
#include "../../handy.h"
#include "../../hexmap.h"
#include "../../log.h"
#include "../../prepend.h"
#include "../../protocol2/blk.h"
#include "../../protocol2/rabin/rconf.h"
#include "../../regexp.h"
#include "../../sbuf.h"
#include "../../slist.h"
#include "../../server/protocol1/restore.h"
#include "../manio.h"
#include "../sdirs.h"
#include "champ_chooser/hash.h"

/* This function reads the manifest to determine whether it may be more
   efficient to just copy the data files across and unpack them on the other
   side. If it thinks it is, it will then do it.
   Return -1 on error, 1 if it copied the data across, 0 if it did not. */
int maybe_restore_spool(struct asfd *asfd, const char *manifest,
	struct sdirs *sdirs, struct bu *bu, int srestore, regex_t *regex,
	struct conf **confs, struct slist *slist,
	enum action act, enum cntr_status cntr_status)
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
	struct sbuf *need_data=NULL;
	int last_ent_was_dir=0;
	char sig[128]="";
	const char *restore_spool=get_string(confs[OPT_RESTORE_SPOOL]);

	// If the client has no restore_spool directory, we have to fall back
	// to the stream style restore.
	if(!restore_spool) return 0;
	
	if(!(manio=manio_open(manifest, "rb", PROTO_2))
	  || !(need_data=sbuf_alloc(PROTO_2))
	  || !(sb=sbuf_alloc(PROTO_2))
	  || !(blk=blk_alloc()))
		goto end;

	while(1)
	{
		if((ars=manio_read_with_blk(manio, sb, blk, NULL))<0)
		{
			logp("Error from manio_read_async() in %s\n",
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

		if(want_to_restore(srestore, sb, regex, confs))
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

	// FIX THIS: should read rabin_avg of a struct rconf.
	estimate_blks=blkcount*RABIN_AVG;
	estimate_one_dat=DATA_FILE_SIG_MAX*RABIN_AVG;
	estimate_dats=datcount*estimate_one_dat;
	printf("%" PRIu64 " blocks = %" PRIu64 " bytes in stream approx\n",
		blkcount, estimate_blks);
	printf("%" PRIu64 " data files = %" PRIu64 " bytes approx\n",
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

	printf("Client is using restore_spool: %s\n", restore_spool);

	if(asfd->write_str(asfd, CMD_GEN, "restore_spool")
	  || asfd_read_expect(asfd, CMD_GEN, "restore_spool_ok"))
		goto end;

	// Send each of the data files that we found to the client.
	HASH_ITER(hh, hash_table, hash_weak, tmpw)
	{
		char msg[32];
		char path[32];
		char *fdatpath=NULL;
		snprintf(path, sizeof(path), "%014" PRIX64, hash_weak->weak);
		path[4]='/';
		path[9]='/';
		snprintf(msg, sizeof(msg), "dat=%s", path);
		printf("got: %s\n", msg);
		if(asfd->write_str(asfd, CMD_GEN, msg)) goto end;
		if(!(fdatpath=prepend_s(sdirs->data, path)))
			goto end;
		if(send_a_file(asfd, fdatpath, get_cntr(confs)))
		{
			free_w(&fdatpath);
			goto end;
		}
		free_w(&fdatpath);
	}

	if(asfd->write_str(asfd, CMD_GEN, "datfilesend")
	  || asfd_read_expect(asfd, CMD_GEN, "datfilesend_ok"))
		goto end;

	manio_close(&manio);
	// Send the manifest to the client.
	if(manio_open(manifest, "rb", PROTO_2))
		goto end;
	blk->got_save_path=0;
	while(1)
	{
		if((ars=manio_read_with_blk(manio, sb, blk, NULL))<0)
		{
			logp("Error from manio_read_async() in %s\n",
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
				"%016" PRIX64 "%s%s",
				blk->fingerprint,
				bytes_to_md5str(blk->md5sum),
				uint64_to_savepathstr_with_sig(blk->savepath));
			if(asfd->write_str(asfd, CMD_SIG, sig))
				goto end;
			blk->got_save_path=0;
			continue;
		}

		sbuf_free_content(need_data);

		if(want_to_restore(srestore, sb, regex, confs))
		{
			if(restore_ent(asfd, &sb, slist, bu, act,
				sdirs, cntr_status, confs,
				need_data, &last_ent_was_dir, manifest))
					goto end;
		}

		sbuf_free_content(sb);
	}

	ret=1;
end:
	blk_free(&blk);
	sbuf_free(&sb);
	sbuf_free(&need_data);
	manio_close(&manio);
	hash_delete_all();
	return ret;
}
