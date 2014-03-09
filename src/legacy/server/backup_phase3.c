#include "include.h"

// Combine the phase1 and phase2 files into a new manifest.
int backup_phase3_server(struct sdirs *sdirs, struct config *cconf,
	int recovery, int compress)
{
	int ars=0;
	int ret=-1;
	int pcmp=0;
	FILE *ucfp=NULL;
	FILE *p2fp=NULL;
	FILE *mp=NULL;
	gzFile mzp=NULL;
	struct sbuf *ucb=NULL;
	struct sbuf *p2b=NULL;
	char *manifesttmp=NULL;

	logp("Begin phase3 (merge manifests)\n");

	if(!(manifesttmp=get_tmp_filename(sdirs->manifest))) goto end;

        if(!(ucfp=open_file(sdirs->unchangeddata, "rb"))
	  || !(p2fp=open_file(sdirs->phase2data, "rb"))
	  || (compress && !(mzp=gzopen_file(manifesttmp, comp_level(cconf))))
          || (!compress && !(mp=open_file(manifesttmp, "wb")))
	  || !(ucb=sbuf_alloc(cconf))
	  || !(p2b=sbuf_alloc(cconf)))
		goto end;

	while(ucfp || p2fp)
	{
		if(ucfp && !ucb->path.buf
		  && (ars=sbufl_fill(ucfp, NULL, ucb, cconf->cntr)))
		{
			if(ars<0) goto end;
			// ars==1 means it ended ok.
			close_fp(&ucfp);
		}
		if(p2fp && !p2b->path.buf
		  && (ars=sbufl_fill(p2fp, NULL, p2b, cconf->cntr)))
		{
			if(ars<0) goto end;
			// ars==1 means it ended ok.
			close_fp(&p2fp);

			// In recovery mode, only want to read to the last
			// entry in the phase 2 file.
			if(recovery) break;
		}

		if(ucb->path.buf && !p2b->path.buf)
		{
			write_status(STATUS_MERGING, ucb->path.buf, cconf);
			if(sbufl_to_manifest(ucb, mp, mzp)) goto end;
			sbuf_free_contents(ucb);
		}
		else if(!ucb->path.buf && p2b->path.buf)
		{
			write_status(STATUS_MERGING, p2b->path.buf, cconf);
			if(sbufl_to_manifest(p2b, mp, mzp)) goto end;
			sbuf_free_contents(p2b);
		}
		else if(!ucb->path.buf && !p2b->path.buf) 
		{
			continue;
		}
		else if(!(pcmp=sbuf_pathcmp(ucb, p2b)))
		{
			// They were the same - write one and free both.
			write_status(STATUS_MERGING, p2b->path.buf, cconf);
			if(sbufl_to_manifest(p2b, mp, mzp)) goto end;
			sbuf_free_contents(ucb);
			sbuf_free_contents(p2b);
		}
		else if(pcmp<0)
		{
			write_status(STATUS_MERGING, ucb->path.buf, cconf);
			if(sbufl_to_manifest(ucb, mp, mzp)) goto end;
			sbuf_free_contents(ucb);
		}
		else
		{
			write_status(STATUS_MERGING, p2b->path.buf, cconf);
			if(sbufl_to_manifest(p2b, mp, mzp)) goto end;
			sbuf_free_contents(p2b);
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

	if(do_rename(manifesttmp, sdirs->manifest))
		goto end;
	else
	{
		unlink(sdirs->phase2data);
		unlink(sdirs->unchangeddata);
	}

	logp("End phase3 (merge manifests)\n");
	ret=0;
end:
	close_fp(&ucfp);
	gzclose_fp(&mzp);
	close_fp(&p2fp);
	close_fp(&mp);
	sbuf_free(ucb);
	sbuf_free(p2b);
	free(manifesttmp);
	return ret;
}
