#include "include.h"

#include "../../server/backup_phase1.h"

// Used on resume, this just reads the phase1 file and sets up the counters.
static int read_phase1(gzFile zp, struct config *conf)
{
	int ars=0;
	struct sbuf *p1b;
	if(!(p1b=sbuf_alloc(conf))) return -1;
	while(1)
	{
		sbuf_free_contents(p1b);
		if((ars=sbufl_fill_phase1(NULL, zp, p1b, conf->p1cntr)))
		{
			// ars==1 means it ended ok.
			if(ars<0)
			{
				sbuf_free(p1b);
				return -1;
			}
			return 0;
		}
		do_filecounter(conf->p1cntr, p1b->path.cmd, 0);

		if(p1b->path.cmd==CMD_FILE
		  || p1b->path.cmd==CMD_ENC_FILE
		  || p1b->path.cmd==CMD_METADATA
		  || p1b->path.cmd==CMD_ENC_METADATA
		  || p1b->path.cmd==CMD_EFS_FILE)
			do_filecounter_bytes(conf->p1cntr,
				(unsigned long long)p1b->statp.st_size);
	}
	sbuf_free(p1b);
	// not reached
	return 0;
}

static int forward_sbuf(FILE *fp, gzFile zp, struct sbuf *b, struct sbuf *target, int isphase1, int seekback, int do_counters, int same, struct dpthl *dpthl, struct config *cconf)
{
	int ars=0;
	off_t pos=0;
	struct sbuf *latest;

	if(!(latest=sbuf_alloc(cconf))) return -1;
	free(latest->burp1);
	latest->burp1=NULL;

	while(1)
	{
		// If told to 'seekback' to the immediately previous
		// entry, we need to remember the position of it.
		if(target && fp && seekback && (pos=ftello(fp))<0)
		{
			logp("Could not ftello in %s(): %s\n", __FUNCTION__,
				strerror(errno));
			goto error;
		}

		if(isphase1)
			ars=sbufl_fill_phase1(fp, zp, b, cconf->cntr);
		else
			ars=sbufl_fill(fp, zp, b, cconf->cntr);

		// Make sure we end up with the highest datapth we can possibly
		// find.
		if(b->burp1->datapth.buf
		  && set_dpthl_from_string(dpthl, b->burp1->datapth.buf, cconf))
		{
			logp("unable to set datapath: %s\n",
				b->burp1->datapth.buf);
			goto error;
		}

		if(ars)
		{
			// ars==1 means it ended ok.
			if(ars<0)
			{
				if(latest->path.buf)
				{
					logp("Error after %s in %s()\n",
					  __FUNCTION__,
					  latest->path.buf?latest->path.buf:"");
				}
				goto error;
			}
			memcpy(b, latest, sizeof(struct sbuf));
			latest->burp1=NULL; // Avoid burp1 getting freed.
			sbuf_free(latest);
			return 0;
		}
//printf("got: %s\n", b->path);
		sbuf_free_contents(latest);
		free(latest->burp1);
		latest->burp1=NULL;

		// If seeking to a particular point...
		if(target && sbuf_pathcmp(target, b)<=0)
		{
			// If told to 'seekback' to the immediately previous
			// entry, do it here.
			if(fp && seekback && fseeko(fp, pos, SEEK_SET))
			{
				logp("Could not fseeko in %s(): %s\n",
					__FUNCTION__, strerror(errno));
				goto error;
			}
			sbuf_free(latest);
			return 0;
		}

		if(do_counters)
		{
			if(same) do_filecounter_same(cconf->cntr, b->path.cmd);
			else do_filecounter_changed(cconf->cntr, b->path.cmd);
			if(b->burp1->endfile.buf)
			{
				unsigned long long e=0;
				e=strtoull(b->burp1->endfile.buf, NULL, 10);
				do_filecounter_bytes(cconf->cntr, e);
				do_filecounter_recvbytes(cconf->cntr, e);
			}
		}

		memcpy(latest, b, sizeof(struct sbuf));
		b->burp1=NULL; // Avoid burp1 getting freed.
		sbuf_free_contents(b);
	}

error:
	sbuf_free(latest);
	return -1;
}

int do_resume(gzFile p1zp, FILE *p2fp, FILE *ucfp, struct dpthl *dpthl, struct config *cconf)
{
	int ret=0;
	struct sbuf *p1b;
	struct sbuf *p2b;
	struct sbuf *p2btmp;
	struct sbuf *ucb;
	if(!(p1b=sbuf_alloc(cconf))
	  || !(p2b=sbuf_alloc(cconf))
	  || !(p2btmp=sbuf_alloc(cconf))
	  || !(ucb=sbuf_alloc(cconf)))
		return -1;

	logp("Begin phase1 (read previous file system scan)\n");
	if(read_phase1(p1zp, cconf)) goto error;

	gzrewind(p1zp);

	logp("Setting up resume positions...\n");
	// Go to the end of p2fp.
	if(forward_sbuf(p2fp, NULL, p2btmp, NULL,
		0, /* not phase1 */
		0, /* no seekback */
		0, /* no counters */
		0, /* changed */
		dpthl, cconf)) goto error;
	rewind(p2fp);
	// Go to the beginning of p2fp and seek forward to the p2btmp entry.
	// This is to guard against a partially written entry at the end of
	// p2fp, which will get overwritten.
	if(forward_sbuf(p2fp, NULL, p2b, p2btmp,
		0, /* not phase1 */
		0, /* no seekback */
		1, /* do_counters */
		0, /* changed */
		dpthl, cconf)) goto error;
	logp("  phase2:    %s (%s)\n", p2b->path, p2b->burp1->datapth);

	// Now need to go to the appropriate places in p1zp and unchanged.
	// The unchanged file needs to be positioned just before the found
	// entry, otherwise it ends up having a duplicated entry.
	if(forward_sbuf(NULL, p1zp, p1b, p2b,
		1, /* phase1 */
		0, /* no seekback */
		0, /* no counters */
		0, /* ignored */
		dpthl, cconf)) goto error;
	logp("  phase1:    %s\n", p1b->path);

	if(forward_sbuf(ucfp, NULL, ucb, p2b,
		0, /* not phase1 */
		1, /* seekback */
		1, /* do_counters */
		1, /* same */
		dpthl, cconf)) goto error;
	logp("  unchanged: %s\n", ucb->path);

	// Now should have all file pointers in the right places to resume.
	if(incr_dpthl(dpthl, cconf)) goto error;

	if(cconf->send_client_counters)
	{
		if(send_counters(cconf)) goto error;
	}

	goto end;
error:
	ret=-1;
end:
	sbuf_free(p1b);
	sbuf_free(p2b);
	sbuf_free(p2btmp);
	sbuf_free(ucb);
	logp("End phase1 (read previous file system scan)\n");
	return ret;
}
