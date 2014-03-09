#include "include.h"

#include "../legacy/burpconfig.h"
#include "../legacy/sbufl.h"

int backup_phase1_server(struct sdirs *sdirs, struct config *conf)
{
	int ars=0;
	int ret=-1;
	int quit=0;
	struct sbuf *sb=NULL;
	gzFile p1zp=NULL;
	char *phase1tmp=NULL;

	logp("Begin phase1 (file system scan)\n");

	if(!(phase1tmp=get_tmp_filename(sdirs->phase1data)))
		goto end;
	if(!(p1zp=gzopen_file(phase1tmp, comp_level(conf))))
		goto end;
	if(!(sb=sbuf_alloc(conf)))
		goto end;

	while(!quit)
	{
		sbuf_free_contents(sb);
		if((ars=sbufl_fill(NULL, NULL, sb, conf->p1cntr)))
		{
			if(ars<0) goto end;
			//ars==1 means it ended ok.
			// Last thing the client sends is 'backupphase2', and
			// it wants an 'ok' reply.
			if(async_write_str(CMD_GEN, "ok")
				|| send_msg_zp(p1zp, CMD_GEN,
					"phase1end", strlen("phase1end")))
				goto end;
			break;
		}
		write_status(STATUS_SCANNING, sb->path.buf, conf);
		if(sbufl_to_manifest_phase1(sb, NULL, p1zp))
			goto end;
		do_filecounter(conf->p1cntr, sb->path.cmd, 0);

		if(sb->path.cmd==CMD_FILE
		  || sb->path.cmd==CMD_ENC_FILE
		  || sb->path.cmd==CMD_METADATA
		  || sb->path.cmd==CMD_ENC_METADATA
		  || sb->path.cmd==CMD_EFS_FILE)
			do_filecounter_bytes(conf->p1cntr,
				(unsigned long long)sb->statp.st_size);
	}

	if(gzclose(p1zp))
	{
		logp("error closing %s in backup_phase1_server\n", phase1tmp);
		goto end;
	}
	if(do_rename(phase1tmp, sdirs->phase1data))
		goto end;

	//print_filecounters(p1cntr, cntr, ACTION_BACKUP);

	logp("End phase1 (file system scan)\n");
	ret=0;
end:
	free(phase1tmp);
	gzclose(p1zp);
	sbuf_free(sb);
	return ret;
}

/*
static enum asl_ret phase1_server_func(struct iobuf *rbuf,
	struct config *conf, void *param)
{
	static struct manio *manio;
	manio=(struct manio *)param;
}

int backup_phase1_server(struct sdirs *sdirs, struct config *conf)
{
	int ret=-1;
	struct manio *manio=NULL;
	logp("Begin phase1 (file system scan)\n");

	if(!(manio=manio_alloc())
	  || manio_init_write(manio, sdirs->phase1data))
		goto end;

	if(async_simple_loop(conf, manio, __FUNCTION__, phase1_server_func))
		goto end;

	ret=0;
end:
	logp("End phase1 (file system scan)\n");
	manio_free(manio);
	return ret;
}
*/
