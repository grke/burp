#include "burp.h"
#include "prog.h"
#include "msg.h"
#include "lock.h"
#include "rs_buf.h"
#include "handy.h"
#include "asyncio.h"
#include "zlibio.h"
#include "counter.h"
#include "dpth.h"
#include "sbuf.h"
#include "backup_phase1_server.h"

int backup_phase1_server(const char *phase1data, const char *client, struct cntr *p1cntr, struct cntr *cntr, struct config *conf)
{
	int ars=0;
	int ret=0;
	int quit=0;
	struct sbuf sb;
	gzFile p1zp=NULL;
	char *phase1tmp=NULL;

	logp("Begin phase1 (file system scan)\n");

	if(!(phase1tmp=get_tmp_filename(phase1data)))
		return -1;

	if(!(p1zp=gzopen_file(phase1tmp, comp_level(conf))))
	{
		free(phase1tmp);
		return -1;
	}

	init_sbuf(&sb);
	while(!quit)
	{
		free_sbuf(&sb);
		if((ars=sbuf_fill(NULL, NULL, &sb, p1cntr)))
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
		write_status(client, STATUS_SCANNING, sb.path, p1cntr, cntr);
		if(sbuf_to_manifest_phase1(&sb, NULL, p1zp))
		{
			ret=-1;
			break;
		}
		do_filecounter(p1cntr, sb.cmd, 0);
	}

        if(p1zp) gzclose(p1zp);
	if(!ret && do_rename(phase1tmp, phase1data))
		ret=-1;
	free(phase1tmp);

	//print_filecounters(p1cntr, cntr, ACTION_BACKUP);

	logp("End phase1 (file system scan)\n");

	return ret;
}
