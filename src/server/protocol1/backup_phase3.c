#include "include.h"

// Combine the phase1 and phase2 files into a new manifest.
int backup_phase3_server_protocol1(struct sdirs *sdirs,
	int compress, struct conf **cconfs)
{
	int ars=0;
	int ret=-1;
	int pcmp=0;
	struct fzp *ucfp=NULL;
	struct fzp *chfp=NULL;
	struct fzp *mzp=NULL;
	struct sbuf *ucb=NULL;
	struct sbuf *chb=NULL;
	char *manifesttmp=NULL;

	logp("Begin phase3 (merge manifests)\n");

	if(!(manifesttmp=get_tmp_filename(sdirs->manifest))) goto end;

        if(!(ucfp=fzp_open(sdirs->unchanged, "rb"))
	  || !(chfp=fzp_open(sdirs->changed, "rb"))
	  || (compress && !(mzp=fzp_gzopen(manifesttmp, comp_level(cconfs))))
          || (!compress && !(mzp=fzp_open(manifesttmp, "wb")))
	  || !(ucb=sbuf_alloc(cconfs))
	  || !(chb=sbuf_alloc(cconfs)))
		goto end;

	while(ucfp || chfp)
	{
		if(ucfp && !ucb->path.buf
		  && (ars=sbufl_fill(ucb, NULL, ucfp, cconfs)))
		{
			if(ars<0) goto end;
			// ars==1 means it ended ok.
			fzp_close(&ucfp);
		}
		if(chfp && !chb->path.buf
		  && (ars=sbufl_fill(chb, NULL, chfp, cconfs)))
		{
			if(ars<0) goto end;
			// ars==1 means it ended ok.
			fzp_close(&chfp);
		}

		if(ucb->path.buf && !chb->path.buf)
		{
			if(write_status(CNTR_STATUS_MERGING,
				ucb->path.buf, cconfs)
			  || sbufl_to_manifest(ucb, mzp)) goto end;
			sbuf_free_content(ucb);
		}
		else if(!ucb->path.buf && chb->path.buf)
		{
			if(write_status(CNTR_STATUS_MERGING,
				chb->path.buf, cconfs)
			  || sbufl_to_manifest(chb, mzp)) goto end;
			sbuf_free_content(chb);
		}
		else if(!ucb->path.buf && !chb->path.buf) 
		{
			continue;
		}
		else if(!(pcmp=sbuf_pathcmp(ucb, chb)))
		{
			// They were the same - write one and free both.
			if(write_status(CNTR_STATUS_MERGING,
				chb->path.buf, cconfs)
			  || sbufl_to_manifest(chb, mzp)) goto end;
			sbuf_free_content(ucb);
			sbuf_free_content(chb);
		}
		else if(pcmp<0)
		{
			if(write_status(CNTR_STATUS_MERGING,
				ucb->path.buf, cconfs)
			  || sbufl_to_manifest(ucb, mzp)) goto end;
			sbuf_free_content(ucb);
		}
		else
		{
			if(write_status(CNTR_STATUS_MERGING,
				chb->path.buf, cconfs)
			  || sbufl_to_manifest(chb, mzp)) goto end;
			sbuf_free_content(chb);
		}
	}

	if(fzp_close(&mzp))
	{
		logp("error gzclosing %s in backup_phase3_server\n",
			manifesttmp);
		goto end;
	}

	// Rename race condition is of no consequence here, as the
	// manifest will just get recreated automatically.
	if(do_rename(manifesttmp, sdirs->manifest))
		goto end;
	else
	{
		unlink(sdirs->changed);
		unlink(sdirs->unchanged);
	}

	logp("End phase3 (merge manifests)\n");
	ret=0;
end:
	fzp_close(&ucfp);
	fzp_close(&mzp);
	fzp_close(&chfp);
	sbuf_free(&ucb);
	sbuf_free(&chb);
	free_w(&manifesttmp);
	return ret;
}
