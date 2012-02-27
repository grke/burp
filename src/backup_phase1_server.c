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

		if(sb.cmd==CMD_FILE
		  || sb.cmd==CMD_ENC_FILE
		  || sb.cmd==CMD_METADATA
		  || sb.cmd==CMD_ENC_METADATA
		  || sb.cmd==CMD_EFS_FILE)
			do_filecounter_bytes(p1cntr,
				(unsigned long long)sb.statp.st_size);
	}

	free_sbuf(&sb);
        if(p1zp) gzclose(p1zp);
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
	struct sbuf p1b;
	init_sbuf(&p1b);
	while(1)
	{
		free_sbuf(&p1b);
		if((ars=sbuf_fill_phase1(NULL, zp, &p1b, p1cntr)))
		{
			// ars==1 means it ended ok.
			if(ars<0)
			{
				free_sbuf(&p1b);
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
	free_sbuf(&p1b);
	// not reached
	return 0;
}

static int forward_sbuf(FILE *fp, gzFile zp, struct sbuf *b, struct sbuf *target, int isphase1, int seekback, int do_counters, int same, struct dpth *dpth, struct config *cconf, struct cntr *cntr)
{
	int ars=0;
	struct sbuf latest;
	init_sbuf(&latest);
	off_t pos=0;
	while(1)
	{
		// If told to 'seekback' to the immediately previous
		// entry, we need to remember the position of it.
		if(target && fp && seekback && (pos=ftello(fp))<0)
		{
			free_sbuf(&latest);
			logp("Could not ftello in forward_sbuf(): %s\n",
				strerror(errno));
			return -1;
		}

		if(isphase1)
			ars=sbuf_fill_phase1(fp, zp, b, cntr);
		else
			ars=sbuf_fill(fp, zp, b, cntr);

		// Make sure we end up with the highest datapth we can possibly
		// find.
		if(b->datapth && set_dpth_from_string(dpth, b->datapth, cconf))
		{
			free_sbuf(b);
			free_sbuf(&latest);
			logp("unable to set datapath: %s\n",
				b->datapth);
			return -1;
		}

		if(ars)
		{
			// ars==1 means it ended ok.
			if(ars<0)
			{
				free_sbuf(b);
				if(latest.path)
				{
					logp("Error after %s in forward_sbuf()\n", latest.path?latest.path:"");
				}
				free_sbuf(&latest);
				return -1;
			}
			memcpy(b, &latest, sizeof(struct sbuf));
			return 0;
		}
//printf("got: %s\n", b->path);
		free_sbuf(&latest);

		// If seeking to a particular point...
		if(target && sbuf_pathcmp(target, b)<=0)
		{
			// If told to 'seekback' to the immediately previous
			// entry, do it here.
			if(fp && seekback && fseeko(fp, pos, SEEK_SET))
			{
				logp("Could not fseeko in forward_sbuf(): %s\n",
					strerror(errno));
				free_sbuf(b);
				free_sbuf(&latest);
				return -1;
			}
			//memcpy(b, &latest, sizeof(struct sbuf));
			return 0;
		}

		if(do_counters)
		{
			do_filecounter(cntr,
			  same?cmd_to_same(b->cmd):cmd_to_changed(b->cmd), 0);
			if(b->endfile)
			{
				unsigned long long e=0;
				e=strtoull(b->endfile, NULL, 10);
				do_filecounter_bytes(cntr, e);
				do_filecounter_recvbytes(cntr, e);
			}
		}

		memcpy(&latest, b, sizeof(struct sbuf));
		init_sbuf(b);
	}
	// Not reached.
	free_sbuf(b);
	free_sbuf(&latest);
	return 0;
}

int do_resume(gzFile p1zp, FILE *p2fp, FILE *ucfp, struct dpth *dpth, struct config *cconf, struct cntr *p1cntr, struct cntr *cntr)
{
	int ret=0;
	struct sbuf p1b;
	struct sbuf p2b;
	struct sbuf p2btmp;
	struct sbuf ucb;
	init_sbuf(&p1b);
	init_sbuf(&p2b);
	init_sbuf(&p2btmp);
	init_sbuf(&ucb);

	logp("Begin phase1 (read previous file system scan)\n");
	if(read_phase1(p1zp, p1cntr)) goto error;

	gzrewind(p1zp);

	logp("Setting up resume positions...\n");
	// Go to the end of p2fp.
	if(forward_sbuf(p2fp, NULL, &p2btmp, NULL,
		0, /* not phase1 */
		0, /* no seekback */
		1, /* do_counters */
		0, /* changed */
		dpth, cconf, cntr)) goto error;
	rewind(p2fp);
	// Go to the beginning of p2fp and seek forward to the p2btmp entry.
	// This is to guard against a partially written entry at the end of
	// p2fp, which will get overwritten.
	if(forward_sbuf(p2fp, NULL, &p2b, &p2btmp,
		0, /* not phase1 */
		0, /* no seekback */
		1, /* do_counters */
		0, /* changed */
		dpth, cconf, cntr)) goto error;
	logp("  phase2:    %s (%s)\n", p2b.path, p2b.datapth);

	// Now need to go to the appropriate places in p1zp and unchanged.
	// The unchanged file needs to be positioned just before the found
	// entry, otherwise it ends up having a duplicated entry.
	if(forward_sbuf(NULL, p1zp, &p1b, &p2b,
		1, /* phase1 */
		0, /* no seekback */
		0, /* no counters */
		0, /* ignored */
		dpth, cconf, cntr)) goto error;
	logp("  phase1:    %s\n", p1b.path);

	if(forward_sbuf(ucfp, NULL, &ucb, &p2b,
		0, /* not phase1 */
		1, /* seekback */
		1, /* do_counters */
		1, /* same */
		dpth, cconf, cntr)) goto error;
	logp("  unchanged: %s\n", ucb.path);

	// Now should have all file pointers in the right places to resume.
	incr_dpth(dpth, cconf);

	goto end;
error:
	ret=-1;
end:
	free_sbuf(&p1b);
	free_sbuf(&p2b);
	free_sbuf(&p2btmp);
	free_sbuf(&ucb);
	logp("End phase1 (read previous file system scan)\n");
	return ret;
}
