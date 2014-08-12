#include "include.h"
#include "../../server/monitor/status_client.h"

// Combine the phase1 and phase2 files into a new manifest.
int backup_phase3_server_burp1(struct sdirs *sdirs,
	int recovery, int compress, struct conf *cconf)
{
	int ars=0;
	int ret=-1;
	int pcmp=0;
	FILE *ucfp=NULL;
	FILE *chfp=NULL;
	FILE *mp=NULL;
	gzFile mzp=NULL;
	struct sbuf *ucb=NULL;
	struct sbuf *chb=NULL;
	char *manifesttmp=NULL;

	logp("Begin phase3 (merge manifests)\n");

	if(!(manifesttmp=get_tmp_filename(sdirs->manifest))) goto end;

        if(!(ucfp=open_file(sdirs->unchanged, "rb"))
	  || !(chfp=open_file(sdirs->changed, "rb"))
	  || (compress && !(mzp=gzopen_file(manifesttmp, comp_level(cconf))))
          || (!compress && !(mp=open_file(manifesttmp, "wb")))
	  || !(ucb=sbuf_alloc(cconf))
	  || !(chb=sbuf_alloc(cconf)))
		goto end;

	while(ucfp || chfp)
	{
		if(ucfp && !ucb->path.buf
		  && (ars=sbufl_fill(ucb, NULL, ucfp, NULL, cconf->cntr)))
		{
			if(ars<0) goto end;
			// ars==1 means it ended ok.
			close_fp(&ucfp);
		}
		if(chfp && !chb->path.buf
		  && (ars=sbufl_fill(chb, NULL, chfp, NULL, cconf->cntr)))
		{
			if(ars<0) goto end;
			// ars==1 means it ended ok.
			close_fp(&chfp);

			// In recovery mode, only want to read to the last
			// entry in the phase 2 file.
			if(recovery) break;
		}

		if(ucb->path.buf && !chb->path.buf)
		{
			if(write_status(STATUS_MERGING, ucb->path.buf, cconf)
			  || sbufl_to_manifest(ucb, mp, mzp)) goto end;
			sbuf_free_content(ucb);
		}
		else if(!ucb->path.buf && chb->path.buf)
		{
			if(write_status(STATUS_MERGING, chb->path.buf, cconf)
			  || sbufl_to_manifest(chb, mp, mzp)) goto end;
			sbuf_free_content(chb);
		}
		else if(!ucb->path.buf && !chb->path.buf) 
		{
			continue;
		}
		else if(!(pcmp=sbuf_pathcmp(ucb, chb)))
		{
			// They were the same - write one and free both.
			if(write_status(STATUS_MERGING, chb->path.buf, cconf)
			  || sbufl_to_manifest(chb, mp, mzp)) goto end;
			sbuf_free_content(ucb);
			sbuf_free_content(chb);
		}
		else if(pcmp<0)
		{
			if(write_status(STATUS_MERGING, ucb->path.buf, cconf)
			  || sbufl_to_manifest(ucb, mp, mzp)) goto end;
			sbuf_free_content(ucb);
		}
		else
		{
			if(write_status(STATUS_MERGING, chb->path.buf, cconf)
			  || sbufl_to_manifest(chb, mp, mzp)) goto end;
			sbuf_free_content(chb);
		}
	}

	if(close_fp(&mp))
	{
		logp("error closing %s in backup_phase3_server\n",
			manifesttmp);
		goto end;
	}
	if(gzclose_fp(&mzp))
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
	close_fp(&ucfp);
	gzclose_fp(&mzp);
	close_fp(&chfp);
	close_fp(&mp);
	sbuf_free(&ucb);
	sbuf_free(&chb);
	free_w(&manifesttmp);
	return ret;
}
