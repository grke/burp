#include "include.h"
#include "../../cmd.h"
#include "dpth.h"

#include "../../server/backup_phase1.h"

// Used on resume, this just reads the phase1 file and sets up cntr.
static int read_phase1(struct fzp *fzp, struct conf **confs)
{
	int ars=0;
	struct sbuf *p1b;
	if(!(p1b=sbuf_alloc(confs))) return -1;
	while(1)
	{
		sbuf_free_content(p1b);
		if((ars=sbufl_fill_phase1(p1b, fzp, confs)))
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

static int do_forward(struct fzp *fzp, struct iobuf *result,
	struct iobuf *target, int isphase1, int seekback, int do_cntr,
	int same, struct dpth *dpth, struct conf **cconfs)
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
		if(target && seekback)
		{
			if(fzp && (pos=fzp_tell(fzp))<0)
			{
				logp("Could not ftello in %s(): %s\n", __func__,
					strerror(errno));
				goto error;
			}
		}

		sbuf_free_content(sb);

		if(isphase1)
			ars=sbufl_fill_phase1(sb, fzp, cconfs);
		else
			ars=sbufl_fill(sb, NULL, fzp, cconfs);

		// Make sure we end up with the highest datapth we can possibly
		// find - dpth_protocol1_set_from_string() will only set it if
		// it is higher.
		if(sb->protocol1->datapth.buf
		  && dpth_protocol1_set_from_string(dpth,
			sb->protocol1->datapth.buf))
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
			if(seekback)
			{
				if(fzp && fzp_seek(fzp, pos, SEEK_SET))
				{
					logp("Could not fseeko in %s(): %s\n",
						__func__, strerror(errno));
					goto error;
				}
			}
			else
			{
				iobuf_free_content(result);
				iobuf_move(result, &sb->path);
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
		iobuf_move(result, &sb->path);
	}

error:
	sbuf_free_content(sb);
	return -1;
}

static int do_resume_work(struct fzp *p1zp, struct fzp *cfp, struct fzp *ucfp,
	struct dpth *dpth, struct conf **cconfs)
{
	int ret=0;
	struct iobuf *p1b=NULL;
	struct iobuf *chb=NULL;
	struct iobuf *ucb=NULL;

	if(!(p1b=iobuf_alloc())
	  || !(chb=iobuf_alloc())
	  || !(ucb=iobuf_alloc()))
		return -1;

	logp("Begin phase1 (read previous file system scan)\n");
	if(read_phase1(p1zp, cconfs)) goto error;

	fzp_seek(p1zp, 0L, SEEK_SET);

	logp("Setting up resume positions...\n");
	// Go to the end of cfp.
	if(do_forward(cfp, chb, NULL,
		0, /* not phase1 */
		0, /* no seekback */
		1, /* do cntr */
		0, /* changed */
		dpth, cconfs)) goto error;
	if(chb->buf)
	{
		logp("  changed:    %s\n", chb->buf);
		// Now need to go to the appropriate places in p1zp and
		// unchanged.
		if(do_forward(p1zp, p1b, chb,
			1, /* phase1 */
			0, /* seekback */
			0, /* no cntr */
			0, /* ignored */
			dpth, cconfs)) goto error;
		logp("  phase1:    %s\n", p1b->buf);
		if(strcmp(p1b->buf, chb->buf))
		{
			logp("phase1 and changed positions should match!\n");
			goto error;
		}

		// The unchanged file needs to be positioned just before the
		// found entry, otherwise it ends up having a duplicated entry.
		if(do_forward(ucfp, ucb, chb,
			0, /* not phase1 */
			1, /* seekback */
			1, /* do_cntr */
			1, /* same */
			dpth, cconfs)) goto error;
		logp("  unchanged: %s\n", ucb->buf);
	}
	else
		logp("  nothing previously transferred\n");

	// Now should have all file pointers in the right places to resume.
	if(dpth_incr(dpth)) goto error;

	if(get_int(cconfs[OPT_SEND_CLIENT_CNTR])
	  && cntr_send(get_cntr(cconfs[OPT_CNTR]))) goto error;

	goto end;
error:
	ret=-1;
end:
	iobuf_free(&p1b);
	iobuf_free(&chb);
	iobuf_free(&ucb);
	logp("End phase1 (read previous file system scan)\n");
	return ret;
}

static int do_truncate(const char *path, struct fzp **fzp)
{
	off_t pos;
	if((pos=fzp_tell(*fzp))<0)
	{
		logp("Could not ftello on %s: %s\n", path, strerror(errno));
		return -1;
	}
	if(truncate(path, pos))
	{
		logp("Could not truncate %s: %s\n", path, strerror(errno));
		return -1;
	}
	return fzp_close(fzp);
}

int do_resume(struct fzp *p1zp, struct sdirs *sdirs,
	struct dpth *dpth, struct conf **cconfs)
{
	int ret=-1;
	struct fzp *cfp=NULL;
	struct fzp *ucfp=NULL;

	// First, open them in a+ mode, so that they will be created if they
	// do not exist.
	if(!(cfp=fzp_open(sdirs->changed, "a+b"))
	  || !(ucfp=fzp_open(sdirs->unchanged, "a+b")))
		goto end;
	fzp_close(&cfp);
	fzp_close(&ucfp);

	// Open for reading.
	if(!(cfp=fzp_open(sdirs->changed, "rb"))
	  || !(ucfp=fzp_open(sdirs->unchanged, "rb")))
		goto end;

	if(do_resume_work(p1zp, cfp, ucfp, dpth, cconfs)) goto end;

	// Truncate to the appropriate places.
	if(do_truncate(sdirs->changed, &cfp)
	  || do_truncate(sdirs->unchanged, &ucfp))
		goto end;
	ret=0;
end:
	fzp_close(&cfp);
	fzp_close(&ucfp);
	return ret;
}
