#include "include.h"
#include "cmd.h"
#include "sdirs.h"

#include "../fzp.h"
#include "../protocol1/sbufl.h"

int backup_phase1_server_all(struct async *as,
	struct sdirs *sdirs, struct conf **confs)
{
	int ars=0;
	int ret=-1;
	struct sbuf *sb=NULL;
	struct fzp *p1zp=NULL;
	char *phase1tmp=NULL;
	struct asfd *asfd=as->asfd;
	enum protocol protocol=get_protocol(confs);
	struct cntr *cntr=get_cntr(confs[OPT_CNTR]);

	logp("Begin phase1 (file system scan)\n");

	if(!(phase1tmp=get_tmp_filename(sdirs->phase1data)))
		goto end;
	if(!(p1zp=fzp_gzopen(phase1tmp, comp_level(confs))))
		goto end;
	if(!(sb=sbuf_alloc(confs)))
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
			  || send_msg_fzp(p1zp, CMD_GEN,
				"phase1end", strlen("phase1end")))
					goto end;
			break;
		}
		if(write_status(CNTR_STATUS_SCANNING, sb->path.buf, confs)
		  || sbuf_to_manifest_phase1(sb, p1zp))
			goto end;
		cntr_add_phase1(cntr, sb->path.cmd, 0);

		if(sb->path.cmd==CMD_FILE
		  || sb->path.cmd==CMD_ENC_FILE
		  || sb->path.cmd==CMD_METADATA
		  || sb->path.cmd==CMD_ENC_METADATA
		  || sb->path.cmd==CMD_EFS_FILE)
		{
			cntr_add_val(cntr, CMD_BYTES_ESTIMATED,
				(unsigned long long)sb->statp.st_size, 0);
		}
	}

	if(fzp_close(&p1zp))
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
	free(phase1tmp);
	fzp_close(&p1zp);
	sbuf_free(&sb);
	return ret;
}
