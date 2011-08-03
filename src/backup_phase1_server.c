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
	char cmd;
	int ret=0;
	int quit=0;
	size_t len=0;
	char *buf=NULL;
	gzFile p1zp=NULL;
	char *phase1tmp=NULL;
	int expect_file_type=0;
	char *lastfile=NULL;

	logp("Begin phase1 (file system scan)\n");

	if(!(phase1tmp=get_tmp_filename(phase1data)))
		return -1;

	if(!(p1zp=gzopen_file(phase1tmp, comp_level(conf))))
	{
		free(phase1tmp);
		return -1;
	}

	while(!quit)
	{
		write_status(client, STATUS_SCANNING, lastfile, p1cntr, cntr);
		if(async_read(&cmd, &buf, &len))
		{
			quit++; ret=-1;
			break;
		}
		if(cmd==CMD_GEN)
		{
			if(!strcmp(buf, "backupphase2"))
			{
				if(async_write_str(CMD_GEN, "ok")
				  || send_msg_zp(p1zp, CMD_GEN,
					"phase1end", strlen("phase1end")))
						ret=-1;
				break;
			}
			else
			{
				quit++; ret=-1;
				logp("unexpected cmd in backupphase1: %c %s\n",
					cmd, buf);
			}
		}
		else if(cmd==CMD_WARNING)
		{
			logp("WARNING: %s\n", buf);
			do_filecounter(p1cntr, cmd, 0);
		}
		else
		{
			if(send_msg_zp(p1zp, cmd, buf, len))
			{
				ret=-1;
				break;
			}
			// TODO - Flaky, do this better
			if(cmd==CMD_STAT) expect_file_type++;
			else if(expect_file_type)
			{
				expect_file_type=0;
				do_filecounter(p1cntr, cmd, 0);
				if(lastfile) free(lastfile);
				lastfile=buf; buf=NULL;
				continue;
			}
		}
		if(buf) { free(buf); buf=NULL; }
	}

	if(buf) { free(buf); buf=NULL; }
	if(lastfile) { free(lastfile); lastfile=NULL; }

        if(p1zp) gzclose(p1zp);
	if(!ret && do_rename(phase1tmp, phase1data))
		ret=-1;
	free(phase1tmp);

	//print_filecounters(p1cntr, cntr, ACTION_BACKUP);

	logp("End phase1 (file system scan)\n");

	return ret;
}
