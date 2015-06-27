#include "../cmd.h"
#include "dpth.h"
#include "resume.h"
#include "backup_phase1.h"
#include "protocol1/dpth.h"

// Used on resume, this just reads the phase1 file and sets up cntr.
static int read_phase1(struct manio *p1manio, struct conf **cconfs)
{
	int ret=-1;
	struct sbuf *p1b;
	struct cntr *cntr=get_cntr(cconfs);
	if(!(p1b=sbuf_alloc(cconfs))) return -1;
	while(1)
	{
		sbuf_free_content(p1b);
		switch(manio_read(p1manio, p1b, cconfs))
		{
			case 0: break;
			case 1: ret=0;
			default: goto end;
		}
		cntr_add_phase1(cntr, p1b->path.cmd, 0);

		if(sbuf_is_filedata(p1b))
			cntr_add_val(cntr, CMD_BYTES_ESTIMATED,
				(unsigned long long)p1b->statp.st_size, 0);
	}
end:
	sbuf_free(&p1b);
	return ret;
}

static int do_forward(struct manio *manio, struct iobuf *result,
	struct iobuf *target, int isphase1, int seekback, int do_cntr,
	int same, struct dpth *dpth, struct conf **cconfs)
{
	int ars=0;
	man_off_t *pos=NULL;
	static struct sbuf *sb=NULL;
	struct cntr *cntr=get_cntr(cconfs);

	if(!sb && !(sb=sbuf_alloc(cconfs)))
		goto error;

	while(1)
	{
		// If told to 'seekback' to the immediately previous
		// entry, we need to remember the position of it.
		if(target && seekback)
		{
			if(manio
			  && !(pos=manio_tell(manio)))
			{
				logp("Could not manio_tell in %s(): %s\n",
					__func__, strerror(errno));
				goto error;
			}
		}

		sbuf_free_content(sb);

		ars=manio_read(manio, sb, cconfs);

		// Make sure we end up with the highest datapth we can possibly
		// find - dpth_protocol1_set_from_string() will only set it if
		// it is higher.
		if(sb->protocol1 && sb->protocol1->datapth.buf
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
			man_off_t_free(&pos);
			return 0;
		}

		// If seeking to a particular point...
		if(target && target->buf && iobuf_pathcmp(target, &sb->path)<=0)
		{
			// If told to 'seekback' to the immediately previous
			// entry, do it here.
			if(seekback)
			{
				errno=0;
				if(manio
				  && manio_seek(manio, pos))
				{
					logp("Could not seek to %s:%d in %s():"
						" %s\n", pos->fpath,
						pos->offset, __func__,
						strerror(errno));
					goto error;
				}
			}
			else
			{
				iobuf_free_content(result);
				iobuf_move(result, &sb->path);
			}
			man_off_t_free(&pos);
			return 0;
		}

		if(do_cntr)
		{
			if(same) cntr_add_same(cntr, sb->path.cmd);
			else cntr_add_changed(cntr, sb->path.cmd);
			if(sb->endfile.buf)
			{
				unsigned long long e=0;
				e=strtoull(sb->endfile.buf, NULL, 10);
				cntr_add_bytes(cntr, e);
				cntr_add_recvbytes(cntr, e);
			}
		}

		iobuf_free_content(result);
		iobuf_move(result, &sb->path);
	}

error:
	sbuf_free_content(sb);
	man_off_t_free(&pos);
	return -1;
}

static int do_resume_work(struct manio *p1manio,
	struct manio *cmanio, struct manio *umanio,
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
	if(read_phase1(p1manio, cconfs)) goto error;

	if(!p1manio)
		manio_seek(p1manio, 0L);

	logp("Setting up resume positions...\n");
	// Go to the end of cmanio.
	if(do_forward(cmanio, chb, NULL,
		0, /* not phase1 */
		0, /* no seekback */
		1, /* do cntr */
		0, /* changed */
		dpth, cconfs)) goto error;
	if(chb->buf)
	{
		logp("  changed:    %s\n", chb->buf);
		// Now need to go to the appropriate places in p1manio and
		// unchanged.
		if(do_forward(p1manio, p1b, chb,
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
		if(do_forward(umanio, ucb, chb,
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
	  && cntr_send(get_cntr(cconfs))) goto error;

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

int do_resume(struct manio *p1manio, struct sdirs *sdirs,
	struct dpth *dpth, struct conf **cconfs)
{
	int ret=-1;
	struct manio *cmanio=NULL;
	struct manio *umanio=NULL;
	enum protocol protocol=get_protocol(cconfs);

	// First, open them in a+ mode, so that they will be created if
	// they do not exist.
	if(!(cmanio=manio_open_phase2(sdirs->changed, "a+b", protocol))
	  || !(umanio=manio_open_phase2(sdirs->unchanged, "a+b", protocol)))
		goto end;
	manio_close(&cmanio);
	manio_close(&umanio);

	if(!(cmanio=manio_open_phase2(sdirs->changed, "rb", protocol))
	  || !(umanio=manio_open_phase2(sdirs->unchanged, "rb", protocol)))
		goto end;

	if(do_resume_work(p1manio, cmanio, umanio, dpth, cconfs)) goto end;

	// Truncate to the appropriate places.
	if(manio_truncate(cmanio, cconfs)
	  || manio_truncate(umanio, cconfs))
		goto end;
	ret=0;
end:
	manio_close(&cmanio);
	manio_close(&umanio);
	return ret;
}
