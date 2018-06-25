#include "../burp.h"
#include "../cmd.h"
#include "../cntr.h"
#include "../iobuf.h"
#include "../log.h"
#include "../pathcmp.h"
#include "../sbuf.h"
#include "dpth.h"
#include "resume.h"
#include "backup_phase1.h"
#include "protocol1/dpth.h"

// Used on resume, this just reads the phase1 file and sets up cntr.
static int read_phase1(struct manio *p1manio, struct conf **cconfs)
{
	int ret=-1;
	struct sbuf *p1b;
	enum protocol protocol=get_protocol(cconfs);
	struct cntr *cntr=get_cntr(cconfs);
	if(!(p1b=sbuf_alloc(protocol))) return -1;
	while(1)
	{
		sbuf_free_content(p1b);
		switch(manio_read(p1manio, p1b))
		{
			case 0: break;
			case 1: ret=0;
			default: goto end;
		}
		cntr_add_phase1(cntr, p1b->path.cmd, 0);

		if(sbuf_is_estimatable(p1b))
			cntr_add_val(cntr, CMD_BYTES_ESTIMATED,
				(uint64_t)p1b->statp.st_size);
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
			iobuf_to_printable(&sb->protocol1->datapth));
		return -1;
	}
	return 0;
}

#ifndef UTEST
static
#endif
int forward_past_entry(struct manio *manio, struct iobuf *target,
	enum protocol protocol, man_off_t **pos)
{
	struct sbuf *sb=NULL;

	if(!(sb=sbuf_alloc(protocol)))
		goto error;

	man_off_t_free(pos);
	if(!(*pos=manio_tell(manio)))
	{
		logp("Could not manio_tell first pos in %s(): %s\n",
			__func__, strerror(errno));
		goto error;
	}

	while(1)
	{
		sbuf_free_content(sb);
		switch(manio_read(manio, sb))
		{
			case 0: break;
			case 1: logp("End of file in %s()\n", __func__);
				goto error;
			default:
				logp("Error in %s()\n", __func__);
				// Treat error in unchanged manio as not OK.
				goto error;
		}

		if(target->cmd==sb->path.cmd
		  && !pathcmp(target->buf, sb->path.buf))
		{
			man_off_t_free(pos);
			if(!(*pos=manio_tell(manio)))
			{
				logp("Could not get pos in %s(): %s\n",
					__func__, strerror(errno));
				goto error;
			}
			sbuf_free(&sb);
			return 0;
		}
	}

error:
	sbuf_free(&sb);
	man_off_t_free(pos);
	return -1;
}

#ifndef UTEST
static
#endif
int forward_before_entry(struct manio *manio, struct iobuf *target,
	struct cntr *cntr, struct dpth *dpth, enum protocol protocol,
	man_off_t **pos)
{
	int ars=0;
	struct sbuf *sb=NULL;

	if(!(sb=sbuf_alloc(protocol)))
		goto error;

	man_off_t_free(pos);
	if(!(*pos=manio_tell(manio)))
	{
		logp("Could not manio_tell first pos in %s(): %s\n",
			__func__, strerror(errno));
		goto error;
	}

	while(1)
	{
		if(sb->endfile.buf
		  || (sb->path.buf && !sbuf_is_filedata(sb)))
		{
			man_off_t_free(pos);
			if(!(*pos=manio_tell(manio)))
			{
				logp("Could not manio_tell pos in %s(): "
					"%s\n", __func__, strerror(errno));
				goto error;
			}
		}

		sbuf_free_content(sb);
		ars=manio_read(manio, sb);
		if(dpth && set_higher_datapth(sb, dpth)) goto error;

		switch(ars)
		{
			case 0: break;
			case 1:
				sbuf_free(&sb);
				return 0;
			default:
				logp("Error in %s(), but continuing\n",
					__func__);
				// Treat error in unchanged manio as
				// OK - could have been a short write.
				sbuf_free(&sb);
				return 0;
		}

		if(iobuf_pathcmp(target, &sb->path)<=0)
		{
			sbuf_free(&sb);
			return 0;
		}

		if(cntr)
		{
			cntr_add_same(cntr, sb->path.cmd);
			if(sb->endfile.buf)
			{
				uint64_t e=strtoull(sb->endfile.buf, NULL, 10);
				cntr_add_bytes(cntr, e);
			}
		}
	}

error:
	sbuf_free(&sb);
	man_off_t_free(pos);
	return -1;
}

#ifndef UTEST
static
#endif
int get_last_good_entry(struct manio *manio, struct iobuf *result,
	struct cntr *cntr, struct dpth *dpth, enum protocol protocol,
	man_off_t **pos)
{
	int ars=0;
	int got_vss_start=0;
	struct sbuf *sb=NULL;
	struct iobuf lastpath;

	if(!(sb=sbuf_alloc(protocol)))
		goto error;

	iobuf_init(&lastpath);

	man_off_t_free(pos);
	if(!(*pos=manio_tell(manio)))
	{
		logp("Could not manio_tell first pos in %s(): %s\n",
			__func__, strerror(errno));
		goto error;
	}

	while(1)
	{
		if(sb->path.buf && !got_vss_start)
		{
			iobuf_free_content(&lastpath);
			iobuf_move(&lastpath, &sb->path);
			if(!sbuf_is_filedata(sb)
			  && !sbuf_is_vssdata(sb))
			{
				iobuf_free_content(result);
				iobuf_move(result, &lastpath);

				man_off_t_free(pos);
				if(!(*pos=manio_tell(manio)))
				{
					logp("Could not manio_tell pos in %s(): %s\n",
						__func__, strerror(errno));
					goto error;
				}
			}
		}
		if(sb->endfile.buf && !got_vss_start)
		{
			iobuf_free_content(result);
			iobuf_move(result, &lastpath);

			man_off_t_free(pos);
			if(!(*pos=manio_tell(manio)))
			{
				logp("Could not manio_tell pos in %s(): %s\n",
					__func__, strerror(errno));
				goto error;
			}
		}

		sbuf_free_content(sb);
		ars=manio_read(manio, sb);
		if(dpth && set_higher_datapth(sb, dpth)) goto error;

		switch(ars)
		{
			case 0: break;
			case 1: iobuf_free_content(&lastpath);
				sbuf_free(&sb);
				return 0;
			default:
				if(result->buf)
					logp("Error after %s in %s()\n",
						iobuf_to_printable(result),
						__func__);
				// Treat error in changed manio as
				// OK - could have been a short write.
				iobuf_free_content(&lastpath);
				sbuf_free(&sb);
				return 0;
		}

		// Some hacks for split_vss.
		switch(sb->path.cmd)
		{
			case CMD_VSS:
			case CMD_ENC_VSS:
				got_vss_start=1;
				break;
			case CMD_VSS_T:
			case CMD_ENC_VSS_T:
				got_vss_start=0;
				break;
			case CMD_FILE:
			case CMD_ENC_FILE:
				if(S_ISDIR(sb->statp.st_mode))
					got_vss_start=0;
				break;
			default:
				break;
		}

		if(cntr)
		{
			// FIX THIS: cannot distinguish between new and
			// changed files.
			cntr_add_changed(cntr, sb->path.cmd);
			if(sb->endfile.buf)
			{
				uint64_t e=strtoull(sb->endfile.buf, NULL, 10);
				cntr_add_bytes(cntr, e);
			}
		}
	}

error:
	iobuf_free_content(&lastpath);
	sbuf_free(&sb);
	man_off_t_free(pos);
	return -1;
}

// Return p1manio position.
static man_off_t *do_resume_work(struct sdirs *sdirs,
	struct dpth *dpth, struct conf **cconfs)
{
	man_off_t *pos=NULL;
	man_off_t *p1pos=NULL;
	struct iobuf *chb=NULL;
	struct manio *cmanio=NULL;
	struct manio *umanio=NULL;
	struct manio *p1manio=NULL;
	enum protocol protocol=get_protocol(cconfs);
	struct cntr *cntr=get_cntr(cconfs);
	int compression=get_int(cconfs[OPT_COMPRESSION]);

	if(!(p1manio=manio_open_phase1(sdirs->phase1data,
		MANIO_MODE_READ, protocol))
	  || !(cmanio=manio_open_phase2(sdirs->changed,
		MANIO_MODE_READ, protocol))
	  || !(umanio=manio_open_phase2(sdirs->unchanged,
		MANIO_MODE_READ, protocol)))
			goto end;

	if(!(chb=iobuf_alloc()))
		return NULL;

	logp("Setting up resume positions...\n");

	if(get_last_good_entry(cmanio, chb, cntr, dpth, protocol, &pos))
		goto error;
	if(manio_close_and_truncate(&cmanio, pos, compression)) goto error;
	man_off_t_free(&pos);
	if(chb->buf)
	{
		logp("  last good entry:    %s\n",
			iobuf_to_printable(chb));
		// Now need to go to the appropriate places in p1manio and
		// unchanged.
		if(forward_past_entry(p1manio, chb, protocol, &p1pos))
			goto error;

		// The unchanged file needs to be positioned just before the
		// found entry, otherwise it ends up having a duplicated entry.
		if(forward_before_entry(umanio,
			chb, cntr, dpth, protocol, &pos))
				goto error;
		if(manio_close_and_truncate(&umanio, pos, compression))
			goto error;
		man_off_t_free(&pos);
	}
	else
	{
		logp("  nothing previously transferred\n");
		if(!(p1pos=manio_tell(p1manio)))
		{
			logp("Could not get p1pos in %s\n", __func__);
			goto error;
		}
		if(!(pos=manio_tell(umanio)))
		{
			logp("Could not get pos in %s\n", __func__);
			goto error;
		}
		if(manio_close_and_truncate(&umanio, pos, compression))
			goto error;
	}

	// Now should have all file pointers in the right places to resume.

	goto end;
error:
	man_off_t_free(&p1pos);
end:
	iobuf_free(&chb);
	man_off_t_free(&pos);
	manio_close(&p1manio);
	manio_close(&cmanio);
	manio_close(&umanio);
	return p1pos;
}

man_off_t *do_resume(struct sdirs *sdirs,
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

	if(dpth_incr(dpth)) goto end;

	logp("End phase1 (read previous file system scan)\n");
end:
	manio_close(&p1manio);
	manio_close(&cmanio);
	manio_close(&umanio);
	return p1pos;
}
