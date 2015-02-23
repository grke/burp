#include "include.h"
#include "../../cmd.h"

#include "../../server/backup_phase1.h"

// Used on resume, this just reads the phase1 file and sets up cntr.
static int read_phase1(gzFile zp, struct conf **confs)
{
	int ars=0;
	struct sbuf *p1b;
	if(!(p1b=sbuf_alloc(confs))) return -1;
	while(1)
	{
		sbuf_free_content(p1b);
		if((ars=sbufl_fill_phase1(p1b, NULL, zp, get_cntr(confs[OPT_CNTR]))))
		{
			// ars==1 means it ended ok.
			if(ars<0)
			{
				sbuf_free(&p1b);
				return -1;
			}
			return 0;
		}
		cntr_add_phase1(get_cntr(confs[OPT_CNTR]), p1b->path.cmd, 0);

		if(p1b->path.cmd==CMD_FILE
		  || p1b->path.cmd==CMD_ENC_FILE
		  || p1b->path.cmd==CMD_METADATA
		  || p1b->path.cmd==CMD_ENC_METADATA
		  || p1b->path.cmd==CMD_EFS_FILE)
			cntr_add_val(get_cntr(confs[OPT_CNTR]), CMD_BYTES_ESTIMATED,
				(unsigned long long)p1b->statp.st_size, 0);
	}
	sbuf_free(&p1b);
	// not reached
	return 0;
}

static int do_forward(FILE *fp, gzFile zp, struct iobuf *result,
	struct iobuf *target, int isphase1, int seekback, int do_cntr,
	int same, struct dpthl *dpthl, struct conf **cconfs)
{
	int ars=0;
	off_t pos=0;
	static struct sbuf *sb=NULL;

	if(!sb && !(sb=sbuf_alloc(cconfs)))
		goto error;

	while(1)
	{
		// If told to 'seekback' to the immediately previous
		// entry, we need to remember the position of it.
		if(target && fp && seekback && (pos=ftello(fp))<0)
		{
			logp("Could not ftello in %s(): %s\n", __func__,
				strerror(errno));
			goto error;
		}

		sbuf_free_content(sb);

		if(isphase1)
			ars=sbufl_fill_phase1(sb, fp, zp,
				get_cntr(cconfs[OPT_CNTR]));
		else
			ars=sbufl_fill(sb, NULL, fp, zp,
				get_cntr(cconfs[OPT_CNTR]));

		// Make sure we end up with the highest datapth we can possibly
		// find - set_dpthl_from_string() will only set it if it is
		// higher.
		if(sb->protocol1->datapth.buf
		  && set_dpthl_from_string(dpthl, sb->protocol1->datapth.buf))
		{
			logp("unable to set datapath: %s\n",
				sb->protocol1->datapth.buf);
			goto error;
		}

		if(ars)
		{
			// ars==1 means it ended ok.
			if(ars<0)
			{
				if(result->buf)
				{
					logp("Error after %s in %s()\n",
						result->buf, __func__);
				}
				goto error;
			}
			return 0;
		}

		// If seeking to a particular point...
		if(target && target->buf && iobuf_pathcmp(target, &sb->path)<=0)
		{
			// If told to 'seekback' to the immediately previous
			// entry, do it here.
			if(fp && seekback && fseeko(fp, pos, SEEK_SET))
			{
				logp("Could not fseeko in %s(): %s\n",
					__func__, strerror(errno));
				goto error;
			}
			return 0;
		}

		if(do_cntr)
		{
			if(same) cntr_add_same(get_cntr(cconfs[OPT_CNTR]), sb->path.cmd);
			else cntr_add_changed(get_cntr(cconfs[OPT_CNTR]), sb->path.cmd);
			if(sb->protocol1->endfile.buf)
			{
				unsigned long long e=0;
				e=strtoull(sb->protocol1->endfile.buf,
					NULL, 10);
				cntr_add_bytes(get_cntr(cconfs[OPT_CNTR]), e);
				cntr_add_recvbytes(get_cntr(cconfs[OPT_CNTR]), e);
			}
		}

		iobuf_free_content(result);
		iobuf_copy(result, &sb->path);
		sb->path.buf=NULL;
	}

error:
	sbuf_free_content(sb);
	return -1;
}

static int forward_fp(FILE *fp, struct iobuf *result, struct iobuf *target,
	int isphase1, int seekback, int do_cntr, int same,
	struct dpthl *dpthl, struct conf **cconfs)
{
	return do_forward(fp, NULL, result, target, isphase1, seekback,
		do_cntr, same, dpthl, cconfs);
}

static int forward_zp(gzFile zp, struct iobuf *result, struct iobuf *target,
	int isphase1, int seekback, int do_cntr, int same,
	struct dpthl *dpthl, struct conf **cconfs)
{
	return do_forward(NULL, zp, result, target, isphase1, seekback,
		do_cntr, same, dpthl, cconfs);
}

static int do_resume_work(gzFile p1zp, FILE *p2fp, FILE *ucfp,
	struct dpthl *dpthl, struct conf **cconfs)
{
	int ret=0;
	struct iobuf *p1b=NULL;
	struct iobuf *p2b=NULL;
	struct iobuf *p2btmp=NULL;
	struct iobuf *ucb=NULL;

	if(!(p1b=iobuf_alloc())
	  || !(p2b=iobuf_alloc())
	  || !(p2btmp=iobuf_alloc())
	  || !(ucb=iobuf_alloc()))
		return -1;

	logp("Begin phase1 (read previous file system scan)\n");
	if(read_phase1(p1zp, cconfs)) goto error;

	gzrewind(p1zp);

	logp("Setting up resume positions...\n");
	// Go to the end of p2fp.
	if(forward_fp(p2fp, p2btmp, NULL,
		0, /* not phase1 */
		0, /* no seekback */
		0, /* no cntr */
		0, /* changed */
		dpthl, cconfs)) goto error;
	rewind(p2fp);
	// Go to the beginning of p2fp and seek forward to the p2btmp entry.
	// This is to guard against a partially written entry at the end of
	// p2fp, which will get overwritten.
	if(forward_fp(p2fp, p2b, p2btmp,
		0, /* not phase1 */
		0, /* no seekback */
		1, /* do_cntr */
		0, /* changed */
		dpthl, cconfs)) goto error;
	logp("  phase2:    %s\n", p2b->buf);

	// Now need to go to the appropriate places in p1zp and unchanged.
	// The unchanged file needs to be positioned just before the found
	// entry, otherwise it ends up having a duplicated entry.
	if(forward_zp(p1zp, p1b, p2b,
		1, /* phase1 */
		0, /* no seekback */
		0, /* no cntr */
		0, /* ignored */
		dpthl, cconfs)) goto error;
	logp("  phase1:    %s\n", p1b->buf);

	if(forward_fp(ucfp, ucb, p2b,
		0, /* not phase1 */
		1, /* seekback */
		1, /* do_cntr */
		1, /* same */
		dpthl, cconfs)) goto error;
	logp("  unchanged: %s\n", ucb->buf);

	// Now should have all file pointers in the right places to resume.
	if(incr_dpthl(dpthl, cconfs)) goto error;

	if(get_int(cconfs[OPT_SEND_CLIENT_CNTR])
	  && cntr_send(get_cntr(cconfs[OPT_CNTR]))) goto error;

	goto end;
error:
	ret=-1;
end:
	iobuf_free(&p1b);
	iobuf_free(&p2b);
	iobuf_free(&p2btmp);
	iobuf_free(&ucb);
	logp("End phase1 (read previous file system scan)\n");
	return ret;
}

static int do_truncate(const char *path, FILE **fp)
{
	off_t pos;
	if((pos=ftello(*fp))<0)
	{
		logp("Could not ftello on %s: %s\n", path, strerror(errno));
		return -1;
	}
	if(truncate(path, pos))
	{
		logp("Could not truncate %s: %s\n", path, strerror(errno));
		return -1;
	}
	close_fp(fp);
	return 0;
}

int do_resume(gzFile p1zp, struct sdirs *sdirs,
	struct dpthl *dpthl, struct conf **cconfs)
{
	int ret=-1;
	FILE *cfp=NULL;
	FILE *ucfp=NULL;

	// First, open them in a+ mode, so that they will be created if they
	// do not exist.
	if(!(cfp=open_file(sdirs->changed, "a+b"))
	  || !(ucfp=open_file(sdirs->unchanged, "a+b")))
		goto end;
	close_fp(&cfp);
	close_fp(&ucfp);

	// Open for reading.
	if(!(cfp=open_file(sdirs->changed, "rb"))
	  || !(ucfp=open_file(sdirs->unchanged, "rb")))
		goto end;

	if(do_resume_work(p1zp, cfp, ucfp, dpthl, cconfs)) goto end;

	// Truncate to the appropriate places.
	if(do_truncate(sdirs->changed, &cfp)
	  || do_truncate(sdirs->unchanged, &ucfp))
		goto end;
	ret=0;
end:
	close_fp(&cfp);
	close_fp(&ucfp);
	return ret;
}

