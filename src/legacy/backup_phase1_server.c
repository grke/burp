#include "include.h"

int backup_phase1_server(const char *phase1data, const char *client, struct config *conf)
{
	int ars=0;
	int ret=0;
	int quit=0;
	struct sbufl sb;
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
		write_status(client, STATUS_SCANNING, sb.path, conf);
		if(sbufl_to_manifest_phase1(&sb, NULL, p1zp))
		{
			ret=-1;
			break;
		}
		do_filecounter(conf->p1cntr, sb.cmd, 0);

		if(sb.cmd==CMD_FILE
		  || sb.cmd==CMD_ENC_FILE
		  || sb.cmd==CMD_METADATA
		  || sb.cmd==CMD_ENC_METADATA
		  || sb.cmd==CMD_EFS_FILE)
			do_filecounter_bytes(conf->p1cntr,
				(unsigned long long)sb.statp.st_size);
	}

	free_sbufl(&sb);
        if(gzclose(p1zp))
	{
		logp("error closing %s in backup_phase1_server\n", phase1tmp);
		ret=-1;
	}
	if(!ret && do_rename(phase1tmp, phase1data))
		ret=-1;
	free(phase1tmp);

	//print_filecounters(p1cntr, cntr, ACTION_BACKUP);

	logp("End phase1 (file system scan)\n");

	return ret;
}


// Used on resume, this just reads the phase1 file and sets up the counters.
static int read_phase1(gzFile zp, struct cntr *p1cntr)
{
	int ars=0;
	struct sbufl p1b;
	init_sbufl(&p1b);
	while(1)
	{
		free_sbufl(&p1b);
		if((ars=sbufl_fill_phase1(NULL, zp, &p1b, p1cntr)))
		{
			// ars==1 means it ended ok.
			if(ars<0)
			{
				free_sbufl(&p1b);
				return -1;
			}
			return 0;
		}
		do_filecounter(p1cntr, p1b.cmd, 0);

		if(p1b.cmd==CMD_FILE
		  || p1b.cmd==CMD_ENC_FILE
		  || p1b.cmd==CMD_METADATA
		  || p1b.cmd==CMD_ENC_METADATA
		  || p1b.cmd==CMD_EFS_FILE)
			do_filecounter_bytes(p1cntr,
				(unsigned long long)p1b.statp.st_size);
	}
	free_sbufl(&p1b);
	// not reached
	return 0;
}

static int forward_sbufl(FILE *fp, gzFile zp, struct sbufl *b, struct sbufl *target, int isphase1, int seekback, int do_counters, int same, struct dpth *dpth, struct config *cconf)
{
	int ars=0;
	struct sbufl latest;
	init_sbufl(&latest);
	off_t pos=0;
	while(1)
	{
		// If told to 'seekback' to the immediately previous
		// entry, we need to remember the position of it.
		if(target && fp && seekback && (pos=ftello(fp))<0)
		{
			free_sbufl(&latest);
			logp("Could not ftello in forward_sbufl(): %s\n",
				strerror(errno));
			return -1;
		}

		if(isphase1)
			ars=sbufl_fill_phase1(fp, zp, b, cconf->cntr);
		else
			ars=sbufl_fill(fp, zp, b, cconf->cntr);

		// Make sure we end up with the highest datapth we can possibly
		// find.
		if(b->datapth && set_dpth_from_string(dpth, b->datapth, cconf))
		{
			free_sbufl(b);
			free_sbufl(&latest);
			logp("unable to set datapath: %s\n",
				b->datapth);
			return -1;
		}

		if(ars)
		{
			// ars==1 means it ended ok.
			if(ars<0)
			{
				free_sbufl(b);
				if(latest.path)
				{
					logp("Error after %s in forward_sbufl()\n", latest.path?latest.path:"");
				}
				free_sbufl(&latest);
				return -1;
			}
			memcpy(b, &latest, sizeof(struct sbufl));
			return 0;
		}
//printf("got: %s\n", b->path);
		free_sbufl(&latest);

		// If seeking to a particular point...
		if(target && sbufl_pathcmp(target, b)<=0)
		{
			// If told to 'seekback' to the immediately previous
			// entry, do it here.
			if(fp && seekback && fseeko(fp, pos, SEEK_SET))
			{
				logp("Could not fseeko in forward_sbufl(): %s\n",
					strerror(errno));
				free_sbufl(b);
				free_sbufl(&latest);
				return -1;
			}
			//memcpy(b, &latest, sizeof(struct sbufl));
			return 0;
		}

		if(do_counters)
		{
			if(same) do_filecounter_same(cconf->cntr, b->cmd);
			else do_filecounter_changed(cconf->cntr, b->cmd);
			if(b->endfile)
			{
				unsigned long long e=0;
				e=strtoull(b->endfile, NULL, 10);
				do_filecounter_bytes(cconf->cntr, e);
				do_filecounter_recvbytes(cconf->cntr, e);
			}
		}

		memcpy(&latest, b, sizeof(struct sbufl));
		init_sbufl(b);
	}
	// Not reached.
	free_sbufl(b);
	free_sbufl(&latest);
	return 0;
}

int do_resume(gzFile p1zp, FILE *p2fp, FILE *ucfp, struct dpth *dpth, struct config *cconf, const char *client)
{
	int ret=0;
	struct sbufl p1b;
	struct sbufl p2b;
	struct sbufl p2btmp;
	struct sbufl ucb;
	init_sbufl(&p1b);
	init_sbufl(&p2b);
	init_sbufl(&p2btmp);
	init_sbufl(&ucb);

	logp("Begin phase1 (read previous file system scan)\n");
	if(read_phase1(p1zp, cconf->p1cntr)) goto error;

	gzrewind(p1zp);

	logp("Setting up resume positions...\n");
	// Go to the end of p2fp.
	if(forward_sbufl(p2fp, NULL, &p2btmp, NULL,
		0, /* not phase1 */
		0, /* no seekback */
		0, /* no counters */
		0, /* changed */
		dpth, cconf)) goto error;
	rewind(p2fp);
	// Go to the beginning of p2fp and seek forward to the p2btmp entry.
	// This is to guard against a partially written entry at the end of
	// p2fp, which will get overwritten.
	if(forward_sbufl(p2fp, NULL, &p2b, &p2btmp,
		0, /* not phase1 */
		0, /* no seekback */
		1, /* do_counters */
		0, /* changed */
		dpth, cconf)) goto error;
	logp("  phase2:    %s (%s)\n", p2b.path, p2b.datapth);

	// Now need to go to the appropriate places in p1zp and unchanged.
	// The unchanged file needs to be positioned just before the found
	// entry, otherwise it ends up having a duplicated entry.
	if(forward_sbufl(NULL, p1zp, &p1b, &p2b,
		1, /* phase1 */
		0, /* no seekback */
		0, /* no counters */
		0, /* ignored */
		dpth, cconf)) goto error;
	logp("  phase1:    %s\n", p1b.path);

	if(forward_sbufl(ucfp, NULL, &ucb, &p2b,
		0, /* not phase1 */
		1, /* seekback */
		1, /* do_counters */
		1, /* same */
		dpth, cconf)) goto error;
	logp("  unchanged: %s\n", ucb.path);

	// Now should have all file pointers in the right places to resume.
	if(incr_dpth(dpth, cconf)) goto error;

	if(cconf->send_client_counters)
	{
		if(send_counters(client, cconf))
			goto error;
	}

	goto end;
error:
	ret=-1;
end:
	free_sbufl(&p1b);
	free_sbufl(&p2b);
	free_sbufl(&p2btmp);
	free_sbufl(&ucb);
	logp("End phase1 (read previous file system scan)\n");
	return ret;
}
