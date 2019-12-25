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
		man_off_t_free(pos);
		if(!(*pos=manio_tell(manio)))
		{
			logp("Could not manio_tell top pos in %s(): %s\n",
				__func__, strerror(errno));
			goto error;
		}

		switch(manio_read(manio, sb))
		{
			case 0:
				break;
			case 1:
				logp("End of file in %s()\n", __func__);
				goto error;
			default:
				logp("Error in %s()\n", __func__);
				goto error;
		}

		switch(iobuf_pathcmp(target, &sb->path))
		{
			case 0:
				// Exact match, we want to be past here.
				if(protocol==PROTO_2
				  && manio->phase==0
				  && !sb->endfile.buf)
				{
					// This is the current manio, and we
					// need one more read to get us past
					// endfile.
					sbuf_free_content(sb);
					switch(manio_read(manio, sb))
					{
						case 0:
							break;
						case 1:
							logp("End of file finishing up in %s()\n", __func__);
							goto error;
						default:
							logp("Error finishing up in %s()\n", __func__);
							goto error;
					}
					if(sb->path.buf)
					{
						logp("Not expecting %s in %s()\n",
							iobuf_to_printable(&sb->path),
							__func__);
						goto error;
					}
					if(!sb->endfile.buf)
					{
						logp("Was expecting endfile in %s()\n",
							__func__);
						goto error;
					}
					// Drop through to tell the position.
				}
				man_off_t_free(pos);
				if(!(*pos=manio_tell(manio)))
				{
					logp("Could not manio_tell pos in %s(): "
						"%s\n", __func__, strerror(errno));
					goto error;
				}
				sbuf_free(&sb);
				return 0;
			case -1:
				// Gone past the match, we want to return to
				// the previous tell.
				sbuf_free(&sb);
				return 0;
			default:
				// Not gone far enough yet, continue.
				break;
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

static int add_to_cntr(
	struct cntr *cntr,
	enum cmd cmd,
	enum cntr_manio cntr_manio
) {
	switch(cntr_manio)
	{
		case CNTR_MANIO_NEW:
			cntr_add(cntr, cmd, 0);
			break;
		case CNTR_MANIO_CHANGED:
			cntr_add_changed(cntr, cmd);
			break;
		case CNTR_MANIO_SAME:
			cntr_add_same(cntr, cmd);
			break;
		case CNTR_MANIO_DELETED:
			cntr_add_deleted(cntr, cmd);
			break;
		default:
			logp("Unknown counter in %s(): %c\n",
				__func__, cntr_manio);
			return -1;
	}
	return 0;
}

static int forward_past_entry_counter(
	struct manio *manio,
	struct iobuf *target,
	struct cntr *cntr,
	man_off_t **pos
) {
	char what[1];
	struct iobuf rbuf;

	iobuf_init(&rbuf);

	while(1)
	{
		iobuf_free_content(&rbuf);
		man_off_t_free(pos);
		if(!(*pos=manio_tell(manio)))
		{
			logp("Could not manio_tell top pos in %s(): %s\n",
				__func__, strerror(errno));
			goto error;
		}

		switch(fzp_read_ensure(manio->fzp, what, sizeof(what), __func__))
		{
			case 0: break;
			case 1: return 0;
			default:
				logp("Error read in %s(), but continuing\n",
					__func__);
				// Treat error in unchanged manio as
				// OK - could have been a short write.
				iobuf_free_content(&rbuf);
				return 0;
		}

		switch(iobuf_fill_from_fzp(&rbuf, manio->fzp))
		{
			case 0: break;
			case 1:
				iobuf_free_content(&rbuf);
				return 0;
			default:
				logp("Error in %s(), but continuing\n",
					__func__);
				// Treat error in unchanged manio as
				// OK - could have been a short write.
				iobuf_free_content(&rbuf);
				return 0;
		}

		switch(iobuf_pathcmp(target, &rbuf))
		{
			case 0:
				add_to_cntr(cntr, rbuf.cmd, what[0]);
				// Exact match, we want to be past here.
				man_off_t_free(pos);
				if(!(*pos=manio_tell(manio)))
				{
					logp("Could not manio_tell pos in %s(): "
						"%s\n", __func__, strerror(errno));
					goto error;
				}
				iobuf_free_content(&rbuf);
				return 0;
			case -1:
				// Gone past the match, we want to return to
				// the previous tell. Do not add_to_cntr,
				// or we will have one too many.
				iobuf_free_content(&rbuf);
				return 0;
			default:
				// Not gone far enough yet, continue.
				add_to_cntr(cntr, rbuf.cmd, what[0]);
				break;
		}
	}

error:
	iobuf_free_content(&rbuf);
	man_off_t_free(pos);
	return -1;
}

static int tell_and_truncate(struct manio **manio, int compression)
{
	int ret=-1;
	man_off_t *pos=NULL;
	if(!(pos=manio_tell(*manio))) {
		logp("Could not get pos in %s\n", __func__);
		goto end;
	}
	if(manio_close_and_truncate(manio, pos, compression))
		goto end;
	ret=0;
end:
	man_off_t_free(&pos);
	return ret;
}

// Return p1manio position.
static int do_resume_work(
	man_off_t **pos_phase1,
	man_off_t **pos_current,
	struct sdirs *sdirs,
	struct dpth *dpth, struct conf **cconfs
) {
	int ret=-1;
	man_off_t *pos=NULL;
	struct iobuf *chb=NULL;
	struct manio *cmanio=NULL;
	struct manio *chmanio=NULL;
	struct manio *unmanio=NULL;
	struct manio *p1manio=NULL;
	struct manio *counters_d=NULL;
	struct manio *counters_n=NULL;
	enum protocol protocol=get_protocol(cconfs);
	struct cntr *cntr=get_cntr(cconfs);
	int compression=get_int(cconfs[OPT_COMPRESSION]);

	if(!(cmanio=manio_open(sdirs->cmanifest,
		MANIO_MODE_READ, protocol))
	  || !(p1manio=manio_open_phase1(sdirs->phase1data,
		MANIO_MODE_READ, protocol))
	  || !(chmanio=manio_open_phase2(sdirs->changed,
		MANIO_MODE_READ, protocol))
	  || !(unmanio=manio_open_phase2(sdirs->unchanged,
		MANIO_MODE_READ, protocol))
	// The counters are always flat files, which is given by PROTO_1.
	  || !(counters_d=manio_open_phase2(sdirs->counters_d,
		MANIO_MODE_READ, PROTO_1))
	  || !(counters_n=manio_open_phase2(sdirs->counters_n,
		MANIO_MODE_READ, PROTO_1)))
			goto end;

	if(!(chb=iobuf_alloc()))
		goto error;

	logp("Setting up resume positions...\n");

	if(get_last_good_entry(chmanio, chb, cntr, dpth, protocol, &pos)
	  || manio_close_and_truncate(&chmanio, pos, compression))
		goto error;

	man_off_t_free(&pos);

	if(chb->buf)
	{
		logp("  last good entry:    %s\n",
			iobuf_to_printable(chb));
		// Now need to go to the appropriate places in p1manio, cmanio
		// and unmanio.

		// This sets pos_phase1.
		if(forward_past_entry(p1manio, chb, protocol, pos_phase1))
			goto error;

		// This sets pos_current. This manifest may not exist.
		if(cmanio->fzp && forward_past_entry(cmanio,
			chb, protocol, pos_current))
				goto error;

		// The unchanged manio needs to be positioned just before the
		// found entry, otherwise it ends up having a duplicated entry.
		if(forward_before_entry(unmanio,
			chb, cntr, dpth, protocol, &pos))
				goto error;
		if(manio_close_and_truncate(&unmanio, pos, compression))
			goto error;
		man_off_t_free(&pos);

		if(forward_past_entry_counter(counters_d, chb, cntr, &pos))
				goto error;
		if(manio_close_and_truncate(&counters_d, pos, 0))
			goto error;
		man_off_t_free(&pos);

		if(forward_past_entry_counter(counters_n, chb, cntr, &pos))
				goto error;
		if(manio_close_and_truncate(&counters_n, pos, 0))
			goto error;
		man_off_t_free(&pos);
	}
	else
	{
		logp("  nothing previously transferred\n");
		if(!(*pos_phase1=manio_tell(p1manio))) {
			logp("Could not get pos_phase1 in %s\n", __func__);
			goto error;
		}
		if(tell_and_truncate(&unmanio, compression)
		 || tell_and_truncate(&counters_d, 0)
		 || tell_and_truncate(&counters_n, 0))
			goto error;
	}

	// Now should have all manios truncated correctly, with pos_phase1 and
	// pos_current set correctly in order to resume.
	ret=0;
	goto end;
error:
	man_off_t_free(pos_phase1);
	man_off_t_free(pos_current);
end:
	iobuf_free(&chb);
	man_off_t_free(&pos);
	manio_close(&p1manio);
	manio_close(&cmanio);
	manio_close(&chmanio);
	manio_close(&unmanio);
	manio_close(&counters_d);
	manio_close(&counters_n);
	return ret;
}

int do_resume(
	man_off_t **pos_phase1,
	man_off_t **pos_current,
	struct sdirs *sdirs,
	struct dpth *dpth,
	struct conf **cconfs
) {
	int ret=-1;
	struct manio *chmanio=NULL;
	struct manio *unmanio=NULL;
	struct manio *p1manio=NULL;
	struct manio *counters_d=NULL;
	struct manio *counters_n=NULL;
	enum protocol protocol=get_protocol(cconfs);

	logp("Begin phase1 (read previous file system scan)\n");
        if(!(p1manio=manio_open_phase1(sdirs->phase1data, "rb", protocol))
	  || read_phase1(p1manio, cconfs))
		goto end;
	manio_close(&p1manio);

	// First, open them in append mode, so that they will be created if
	// they do not exist.
	if(!(chmanio=manio_open_phase2(sdirs->changed, "ab", protocol))
	  || !(unmanio=manio_open_phase2(sdirs->unchanged, "ab", protocol))
	  || !(counters_d=manio_open_phase2(sdirs->counters_d, "ab", PROTO_1))
	  || !(counters_n=manio_open_phase2(sdirs->counters_n, "ab", PROTO_1)))
		goto end;
	manio_close(&chmanio);
	manio_close(&unmanio);
	manio_close(&counters_d);
	manio_close(&counters_n);

	if(do_resume_work(pos_phase1, pos_current, sdirs, dpth, cconfs))
		goto end;

	if(dpth_incr(dpth)) goto end;

	logp("End phase1 (read previous file system scan)\n");
	ret=0;
end:
	manio_close(&p1manio);
	manio_close(&chmanio);
	manio_close(&unmanio);
	manio_close(&counters_d);
	manio_close(&counters_n);
	return ret;
}
