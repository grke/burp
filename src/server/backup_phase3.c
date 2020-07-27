#include "../burp.h"
#include "../alloc.h"
#include "../cntr.h"
#include "../conf.h"
#include "../cstat.h"
#include "../fsops.h"
#include "../handy.h"
#include "../log.h"
#include "../sbuf.h"
#include "compress.h"
#include "manio.h"
#include "sdirs.h"
#include "child.h"
#include "backup_phase3.h"

static const char *get_rmanifest_relative(struct sdirs *sdirs,
	struct conf **confs)
{
	size_t s;
	const char *directory;

	directory=get_string(confs[OPT_DIRECTORY]);
	s=strlen(directory);

	if(!strncmp(sdirs->rmanifest, directory, s))
	{
		const char *cp;
		cp=sdirs->rmanifest+strlen(directory);
		while(cp && *cp=='/') cp++;
		return cp;
	}
	return sdirs->rmanifest;
}

// Combine the phase1 and phase2 files into a new manifest.
int backup_phase3_server_all(struct sdirs *sdirs, struct conf **confs)
{
	int ret=-1;
	int pcmp=0;
	struct sbuf *usb=NULL;
	struct sbuf *csb=NULL;
	char *manifesttmp=NULL;
	struct manio *newmanio=NULL;
	struct manio *chmanio=NULL;
	struct manio *unmanio=NULL;
	enum protocol protocol=get_protocol(confs);
	const char *rmanifest_relative=NULL;
	char *seed_src=get_string(confs[OPT_SEED_SRC]);
	char *seed_dst=get_string(confs[OPT_SEED_DST]);

	logp("Begin phase3 (merge manifests)\n");

	if(protocol==PROTO_2)
		rmanifest_relative=get_rmanifest_relative(sdirs, confs);

	if(!(manifesttmp=get_tmp_filename(sdirs->manifest))
	  || !(newmanio=manio_open_phase3(manifesttmp,
		comp_level(get_int(confs[OPT_COMPRESSION])),
		protocol, rmanifest_relative))
	  || !(chmanio=manio_open_phase2(sdirs->changed, "rb", protocol))
	  || !(unmanio=manio_open_phase2(sdirs->unchanged, "rb", protocol))
	  || !(usb=sbuf_alloc(protocol))
	  || !(csb=sbuf_alloc(protocol)))
		goto end;

	while(chmanio || unmanio)
	{
		if(unmanio
		  && !usb->path.buf)
		{
			switch(manio_read(unmanio, usb))
			{
				case -1:
					goto end;
				case 1:
					manio_close(&unmanio);
					break;
			}
		}

		if(chmanio
		  && !csb->path.buf)
		{
			switch(manio_read(chmanio, csb))
			{
				case -1:
					goto end;
				case 1:
					manio_close(&chmanio);
					break;
			}
		}

		if(usb->path.buf && !csb->path.buf)
		{
			if(timed_operation_status_only(CNTR_STATUS_MERGING,
				usb->path.buf, confs)) goto end;
			switch(manio_copy_entry(usb, usb, unmanio, newmanio,
				seed_src, seed_dst))
			{
				case -1: goto end;
				case 1: manio_close(&unmanio);
			}
		}
		else if(!usb->path.buf && csb->path.buf)
		{
			if(timed_operation_status_only(CNTR_STATUS_MERGING,
				csb->path.buf, confs)) goto end;
			switch(manio_copy_entry(csb, csb, chmanio, newmanio,
				seed_src, seed_dst))
			{
				case -1: goto end;
				case 1: manio_close(&chmanio);
			}
		}
		else if(!usb->path.buf && !csb->path.buf)
		{
			continue;
		}
		else if(!(pcmp=sbuf_pathcmp(usb, csb)))
		{
			// They were the same - write one.
			if(timed_operation_status_only(CNTR_STATUS_MERGING,
				csb->path.buf, confs)) goto end;
			switch(manio_copy_entry(csb, csb, chmanio, newmanio,
				seed_src, seed_dst))
			{
				case -1: goto end;
				case 1: manio_close(&chmanio);
			}
		}
		else if(pcmp<0)
		{
			if(timed_operation_status_only(CNTR_STATUS_MERGING,
				usb->path.buf, confs)) goto end;
			switch(manio_copy_entry(usb, usb, unmanio, newmanio,
				seed_src, seed_dst))
			{
				case -1: goto end;
				case 1: manio_close(&unmanio);
			}
		}
		else
		{
			if(timed_operation_status_only(CNTR_STATUS_MERGING,
				csb->path.buf, confs)) goto end;
			switch(manio_copy_entry(csb, csb, chmanio, newmanio,
				seed_src, seed_dst))
			{
				case -1: goto end;
				case 1: manio_close(&chmanio);
			}
		}
	}

	// Flush to disk.
	if(manio_close(&newmanio))
	{
		logp("error gzclosing %s in backup_phase3_server\n",
			manifesttmp);
		goto end;
	}

	// Rename race condition should be of no consequence here, as the
	// manifest should just get recreated automatically.
	if(do_rename(manifesttmp, sdirs->manifest))
		goto end;
	else
	{
		recursive_delete(sdirs->changed);
		recursive_delete(sdirs->unchanged);
	}

	logp("End phase3 (merge manifests)\n");
	ret=0;
end:
	manio_close(&newmanio);
	manio_close(&chmanio);
	manio_close(&unmanio);
	sbuf_free(&csb);
	sbuf_free(&usb);
	free_w(&manifesttmp);
	return ret;
}
