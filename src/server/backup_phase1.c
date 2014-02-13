#include "include.h"

#include "../legacy/burpconfig.h"
#include "../legacy/sbufl.h"

int backup_phase1_server(struct sdirs *sdirs, struct config *conf)
{
	int ars=0;
	int ret=0;
	int quit=0;
	struct sbufl sb;
	gzFile p1zp=NULL;
	char *phase1tmp=NULL;

	logp("Begin phase1 (file system scan)\n");

	if(!(phase1tmp=get_tmp_filename(sdirs->phase1data)))
		return -1;

	if(!(p1zp=gzopen_file(phase1tmp, comp_level(conf))))
	{
		free(phase1tmp);
		return -1;
	}

	init_sbufl(&sb);
	while(!quit)
	{
		free_sbufl(&sb);
		if((ars=sbufl_fill(NULL, NULL, &sb, conf->p1cntr)))
		{
			if(ars<0) ret=-1;
			//ars==1 means it ended ok.
			// Last thing the client sends is 'backupphase2', and
			// it wants an 'ok' reply.
			if(async_write_str(CMD_GEN, "ok")
				|| send_msg_zp(p1zp, CMD_GEN,
					"phase1end", strlen("phase1end")))
				ret=-1;
			break;
		}
		write_status(STATUS_SCANNING, sb.path.buf, conf);
		if(sbufl_to_manifest_phase1(&sb, NULL, p1zp))
		{
			ret=-1;
			break;
		}
		do_filecounter(conf->p1cntr, sb.path.cmd, 0);

		if(sb.path.cmd==CMD_FILE
		  || sb.path.cmd==CMD_ENC_FILE
		  || sb.path.cmd==CMD_METADATA
		  || sb.path.cmd==CMD_ENC_METADATA
		  || sb.path.cmd==CMD_EFS_FILE)
			do_filecounter_bytes(conf->p1cntr,
				(unsigned long long)sb.statp.st_size);
	}

	free_sbufl(&sb);
	if(gzclose(p1zp))
	{
		logp("error closing %s in backup_phase1_server\n", phase1tmp);
		ret=-1;
	}
	if(!ret && do_rename(phase1tmp, sdirs->phase1data))
		ret=-1;
	free(phase1tmp);

	//print_filecounters(p1cntr, cntr, ACTION_BACKUP);

	logp("End phase1 (file system scan)\n");

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
