#include "../cmd.h"
#include "dpth.h"
#include "resume2.h"
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

static int set_higher_datapth(struct sbuf *sb, struct dpth *dpth)
{
	// Make sure we end up with the highest datapth we can possibly
	// find - dpth_protocol1_set_from_string() will only set it if
	// it is higher.
	if(sb->protocol1 && sb->protocol1->datapth.buf
	  && dpth_protocol1_set_from_string(dpth,
		sb->protocol1->datapth.buf))
	{
		logp("unable to set datapath: %s\n",
			sb->protocol1->datapth.buf);
		return -1;
	}
	return 0;
}

int do_forward(struct manio *manio, struct iobuf *result,
	struct iobuf *target, struct cntr *cntr,
	int same, struct dpth *dpth, struct conf **cconfs,
	man_off_t **pos, man_off_t **lastpos)
{
	int ars=0;
	static struct sbuf *sb=NULL;
	struct iobuf *lastpath=NULL;

	if(!sb && !(sb=sbuf_alloc(cconfs)))
		goto error;
	if(!lastpath && !(lastpath=iobuf_alloc()))
		goto error;

	man_off_t_free(pos);
	if(!(*pos=manio_tell(manio)))
	{
		logp("Could not manio_tell first pos in %s(): %s\n",
			__func__, strerror(errno));
		goto error;
	}
	man_off_t_free(lastpos);
	if(!(*lastpos=manio_tell(manio)))
	{
		logp("Could not manio_tell first lastpos in %s(): %s\n",
			__func__, strerror(errno));
		goto error;
	}

	while(1)
	{
		if(sb->endfile.buf || manio->phase==1)
		{
			man_off_t_free(lastpos);
			if(!(*lastpos=manio_tell(manio)))
			{
				logp("Could not manio_tell lastpos in %s(): "
					"%s\n", __func__, strerror(errno));
				goto error;
			}
			iobuf_free_content(result);
			iobuf_move(result, lastpath);
		}
		if(sb->path.buf)
		{
			iobuf_free_content(lastpath);
			iobuf_move(lastpath, &sb->path);
		}

		sbuf_free_content(sb);
		ars=manio_read(manio, sb, cconfs);
		if(dpth && set_higher_datapth(sb, dpth)) goto error;

		switch(ars)
		{
			case 0: break;
			case 1: return 0;
			default:
				if(result->buf)
					logp("Error after %s in %s()\n",
						result->buf, __func__);
				if(manio->phase!=1 || same)
				{
					// Treat error in changed manio as
					// OK - could have been a short write.
					return 0;
				}
				goto error;
		}

		man_off_t_free(pos);
		if(!(*pos=manio_tell(manio)))
		{
			logp("Could not manio_tell pos in %s(): %s\n",
				__func__, strerror(errno));
			goto error;
		}

		// If seeking to a particular point...
		if(target
		  && target->buf
		  && iobuf_pathcmp(target, &sb->path)<=0)
		{
			iobuf_free_content(result);
			iobuf_move(result, &sb->path);
			return 0;
		}

		if(cntr)
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
	}

error:
	sbuf_free_content(sb);
	man_off_t_free(pos);
	man_off_t_free(lastpos);
	return -1;
}

// Return p1manio position.
static man_off_t *do_resume_work(struct sdirs *sdirs,
	struct dpth *dpth, struct conf **cconfs)
{
	man_off_t *pos=NULL;
	man_off_t *lastpos=NULL;
	man_off_t *p1pos=NULL;
	struct iobuf *p1b=NULL;
	struct iobuf *chb=NULL;
	struct iobuf *ucb=NULL;
	struct manio *cmanio=NULL;
	struct manio *umanio=NULL;
	struct manio *p1manio=NULL;
	enum protocol protocol=get_protocol(cconfs);
	struct cntr *cntr=get_cntr(cconfs);

	if(!(p1manio=manio_open_phase1(sdirs->phase1data, "rb", protocol))
	  || !(cmanio=manio_open_phase2(sdirs->changed, "rb", protocol))
	  || !(umanio=manio_open_phase2(sdirs->unchanged, "rb", protocol)))
		goto end;

	if(!(p1b=iobuf_alloc())
	  || !(chb=iobuf_alloc())
	  || !(ucb=iobuf_alloc()))
		return NULL;

	logp("Setting up resume positions...\n");

	// Go to the end of cmanio.
	if(do_forward(cmanio, chb, NULL,
		cntr,
		0, /* changed */
		dpth, cconfs, &pos, &lastpos)) goto error;
	//if(manio_truncate(cmanio, pos, cconfs)) goto error;
	if(manio_truncate(cmanio, lastpos, cconfs)) goto error;
	manio_close(&cmanio);
	man_off_t_free(&pos);
	man_off_t_free(&lastpos);
	if(chb->buf)
	{
		logp("  changed:    %s\n", chb->buf);
		// Now need to go to the appropriate places in p1manio and
		// unchanged.
		if(do_forward(p1manio, p1b, chb,
			NULL, /* no cntr */
			0, /* ignored */
			dpth, cconfs, &p1pos, &lastpos)) goto error;
		logp("  phase1:    %s\n", p1b->buf);
		man_off_t_free(&lastpos);

		if(strcmp(p1b->buf, chb->buf))
		{
			logp("phase1 and changed positions should match!\n");
			goto error;
		}

		// The unchanged file needs to be positioned just before the
		// found entry, otherwise it ends up having a duplicated entry.
		if(do_forward(umanio, ucb, chb,
			cntr,
			1, /* same */
			dpth, cconfs, &pos, &lastpos)) goto error;
		logp("  unchanged: %s\n", ucb->buf);
		if(manio_truncate(umanio, lastpos, cconfs)) goto error;
		manio_close(&umanio);
		man_off_t_free(&pos);
		man_off_t_free(&lastpos);
	}
	else
	{
		logp("  nothing previously transferred\n");
		if(!(p1pos=manio_tell(p1manio)))
			goto error;
		if(!(pos=manio_tell(umanio)))
			goto error;
		if(manio_truncate(umanio, pos, cconfs))
			goto error;
	}

	// Now should have all file pointers in the right places to resume.
	if(dpth_incr(dpth)) goto error;

	if(get_int(cconfs[OPT_SEND_CLIENT_CNTR])
	  && cntr_send(get_cntr(cconfs))) goto error;

	goto end;
error:
	man_off_t_free(&p1pos);
end:
	iobuf_free(&p1b);
	iobuf_free(&chb);
	iobuf_free(&ucb);
	man_off_t_free(&pos);
	manio_close(&p1manio);
	manio_close(&cmanio);
	manio_close(&umanio);
	return p1pos;
}

man_off_t *do_resume2(struct sdirs *sdirs,
	struct dpth *dpth, struct conf **cconfs)
{
	man_off_t *p1pos=NULL;
	struct manio *cmanio=NULL;
	struct manio *umanio=NULL;
	struct manio *p1manio=NULL;
	enum protocol protocol=get_protocol(cconfs);

	logp("Begin phase1 (read previous file system scan)\n");
        if(!(p1manio=manio_open_phase1(sdirs->phase1data, "rb", protocol))
	  || read_phase1(p1manio, cconfs))
		goto end;
	manio_close(&p1manio);

	// First, open them in append mode, so that they will be created if
	// they do not exist.
	if(!(cmanio=manio_open_phase2(sdirs->changed, "ab", protocol))
	  || !(umanio=manio_open_phase2(sdirs->unchanged, "ab", protocol)))
		goto end;
	manio_close(&cmanio);
	manio_close(&umanio);

	if(!(p1pos=do_resume_work(sdirs, dpth, cconfs))) goto end;

	logp("End phase1 (read previous file system scan)\n");
end:
	manio_close(&p1manio);
	manio_close(&cmanio);
	manio_close(&umanio);
	return p1pos;
}
