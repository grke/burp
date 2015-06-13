#include "include.h"
#include "../../server/manio.h"
#include "../../server/sdirs.h"

static const char *get_rmanifest_relative(struct sdirs *sdirs,
	struct conf **confs)
{
	const char *cp;
	cp=sdirs->rmanifest+strlen(get_string(confs[OPT_DIRECTORY]));
	while(cp && *cp=='/') cp++;
	return cp;
}

// This is basically backup_phase3_server() from protocol1. It used to merge the
// unchanged and changed data into a single file. Now it splits the manifests
// into several files.
int backup_phase3_server_protocol2(struct sdirs *sdirs, struct conf **confs)
{
	int ret=1;
	int pcmp=0;
	struct blk *blk=NULL;
	struct sbuf *usb=NULL;
	struct sbuf *csb=NULL;
	char *manifesttmp=NULL;
	struct manio *newmanio=NULL;
	struct manio *chmanio=NULL;
	struct manio *unmanio=NULL;
	enum protocol protocol=get_protocol(confs);
	const char *rmanifest_relative=get_rmanifest_relative(sdirs, confs);

	logp("Begin phase3 (merge manifests)\n");

	if(!(manifesttmp=get_tmp_filename(sdirs->rmanifest))
	  || !(newmanio=manio_open_phase3(manifesttmp, comp_level(confs),
		protocol, rmanifest_relative))
	  || !(chmanio=manio_open_phase2(sdirs->changed, "rb", protocol))
	  || !(unmanio=manio_open_phase2(sdirs->unchanged, "rb", protocol))
	  || !(usb=sbuf_alloc(confs))
	  || !(csb=sbuf_alloc(confs)))
		goto end;

	while(chmanio || unmanio)
	{
		if(!blk && !(blk=blk_alloc())) goto end;

		if(unmanio
		  && !usb->path.buf)
		{
			switch(manio_read(unmanio, usb, confs))
			{
				case -1: goto end;
				case 1: manio_close(&unmanio);
			}
		}

		if(chmanio
		  && !csb->path.buf)
		{
			switch(manio_read(chmanio, csb, confs))
			{
				case -1: goto end;
				case 1: manio_close(&chmanio);
			}
		}

		if(usb->path.buf && !csb->path.buf)
		{
			switch(manio_copy_entry(NULL /* no async */,
				usb, usb, &blk, unmanio, newmanio, confs))
			{
				case -1: goto end;
				case 1: manio_close(&unmanio);
			}
		}
		else if(!usb->path.buf && csb->path.buf)
		{
			switch(manio_copy_entry(NULL /* no async */,
				csb, csb, &blk, chmanio, newmanio, confs))
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
			switch(manio_copy_entry(NULL /* no async */,
				csb, csb, &blk, chmanio, newmanio, confs))
			{
				case -1: goto end;
				case 1: manio_close(&chmanio);
			}
		}
		else if(pcmp<0)
		{
			switch(manio_copy_entry(NULL /* no async */,
				usb, usb, &blk, unmanio, newmanio, confs))
			{
				case -1: goto end;
				case 1: manio_close(&unmanio);
			}
		}
		else
		{
			switch(manio_copy_entry(NULL /* no async */,
				csb, csb, &blk, chmanio, newmanio, confs))
			{
				case -1: goto end;
				case 1: manio_close(&chmanio);
			}
		}
	}

	// Flush to disk.
	if(manio_close(&newmanio)) goto end;

	// Rename race condition should be of no consequence here, as the
	// manifest should just get recreated automatically.
	if(do_rename(manifesttmp, sdirs->rmanifest))
		goto end;
	else
	{
		recursive_delete(sdirs->changed, NULL, 1);
		recursive_delete(sdirs->unchanged, NULL, 1);
	}

	logp("End phase3 (merge manifests)\n");
	ret=0;
end:
	manio_close(&newmanio);
	manio_close(&chmanio);
	manio_close(&unmanio);
	sbuf_free(&csb);
	sbuf_free(&usb);
	blk_free(&blk);
	free_w(&manifesttmp);
	return ret;
}
