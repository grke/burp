#include "include.h"
#include "monitor/status_client.h"

#include "../burp1/sbufl.h"

int backup_phase1_server_all(struct async *as,
	struct sdirs *sdirs, struct conf *conf)
{
	int ars=0;
	int ret=-1;
	struct sbuf *sb=NULL;
	gzFile p1zp=NULL;
	char *phase1tmp=NULL;
	struct asfd *asfd=as->asfd;

	logp("Begin phase1 (file system scan)\n");

	if(!(phase1tmp=get_tmp_filename(sdirs->phase1data)))
		goto end;
	if(!(p1zp=gzopen_file(phase1tmp, comp_level(conf))))
		goto end;
	if(!(sb=sbuf_alloc(conf)))
		goto end;

	while(1)
	{
		sbuf_free_content(sb);
		if(conf->protocol==PROTO_BURP1)
			ars=sbufl_fill(sb, asfd, NULL, NULL, conf->cntr);
		else
			ars=sbuf_fill(sb, asfd, NULL, NULL, NULL, conf);

		if(ars)
		{
			if(ars<0) goto end;
			//ars==1 means it ended ok.
			// Last thing the client sends is 'backupphase2', and
			// it wants an 'ok' reply.
			if(asfd->write_str(asfd, CMD_GEN, "ok")
			  || send_msg_zp(p1zp, CMD_GEN,
				"phase1end", strlen("phase1end")))
					goto end;
			break;
		}
		if(write_status(STATUS_SCANNING, sb->path.buf, conf)
		  || sbufl_to_manifest_phase1(sb, NULL, p1zp))
			goto end;
		cntr_add_phase1(conf->cntr, sb->path.cmd, 0);

		if(sb->path.cmd==CMD_FILE
		  || sb->path.cmd==CMD_ENC_FILE
		  || sb->path.cmd==CMD_METADATA
		  || sb->path.cmd==CMD_ENC_METADATA
		  || sb->path.cmd==CMD_EFS_FILE)
			cntr_add_val(conf->cntr, CMD_BYTES_ESTIMATED,
				(unsigned long long)sb->statp.st_size, 0);
	}

	if(gzclose_fp(&p1zp))
	{
		logp("error closing %s in backup_phase1_server\n", phase1tmp);
		goto end;
	}
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
	gzclose_fp(&p1zp);
	sbuf_free(&sb);
	return ret;
}
