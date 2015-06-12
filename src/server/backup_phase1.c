#include "include.h"
#include "cmd.h"
#include "manio.h"
#include "sdirs.h"

#include "../protocol1/sbufl.h"

int backup_phase1_server_all(struct async *as,
	struct sdirs *sdirs, struct conf **confs)
{
	int ars=0;
	int ret=-1;
	struct sbuf *sb=NULL;
	char *phase1tmp=NULL;
	struct asfd *asfd=as->asfd;
	struct manio *manio=NULL;
	enum protocol protocol=get_protocol(confs);
	struct cntr *cntr=get_cntr(confs);

	logp("Begin phase1 (file system scan)\n");

	if(!(phase1tmp=get_tmp_filename(sdirs->phase1data))
	  || !(manio=manio_open_phase1(phase1tmp,
		comp_level(confs), protocol))
	  || !(sb=sbuf_alloc(confs)))
		goto end;

	while(1)
	{
		sbuf_free_content(sb);
		if(protocol==PROTO_1)
			ars=sbufl_fill(sb, asfd, NULL, confs);
		else
			ars=sbuf_fill(sb, asfd, NULL, NULL, NULL, confs);

		if(ars)
		{
			if(ars<0) goto end;
			//ars==1 means it ended ok.
			// Last thing the client sends is 'backupphase2', and
			// it wants an 'ok' reply.
			if(asfd->write_str(asfd, CMD_GEN, "ok")
			  || send_msg_fzp(manio->fzp, CMD_GEN,
				"phase1end", strlen("phase1end")))
					goto end;
			break;
		}
		if(write_status(CNTR_STATUS_SCANNING, sb->path.buf, confs)
		  || manio_write_sbuf(manio, sb))
			goto end;
		cntr_add_phase1(cntr, sb->path.cmd, 0);

		if(sbuf_is_filedata(sb))
		{
			cntr_add_val(cntr, CMD_BYTES_ESTIMATED,
				(unsigned long long)sb->statp.st_size, 0);
		}
	}

	if(manio_close(&manio))
	{
		logp("error closing %s in backup_phase1_server\n", phase1tmp);
		goto end;
	}

	if(check_quota(as, confs))
		goto end;

	// Possible rename race condition is of no consequence here, because
	// the working directory will always get deleted if phase1 is not
	// complete.
	if(do_rename(phase1tmp, sdirs->phase1data))
		goto end;

	//cntr_print(p1cntr, cntr, ACTION_BACKUP);

	logp("End phase1 (file system scan)\n");
	ret=0;
end:
	free_w(&phase1tmp);
	manio_close(&manio);
	sbuf_free(&sb);
	return ret;
}
