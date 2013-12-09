#include "include.h"

// Combine the phase1 and phase2 files into a new manifest.
int backup_phase3_server(const char *phase2data, const char *unchangeddata, const char *manifest, int recovery, int compress, const char *client, struct cntr *p1cntr, struct cntr *cntr, struct config *cconf)
{
	int ars=0;
	int ret=0;
	int pcmp=0;
	FILE *ucfp=NULL;
	FILE *p2fp=NULL;
	FILE *mp=NULL;
	gzFile mzp=NULL;
	struct sbufl ucb;
	struct sbufl p2b;
	char *manifesttmp=NULL;

	logp("Begin phase3 (merge manifests)\n");

	if(!(manifesttmp=get_tmp_filename(manifest))) return -1;

        if(!(ucfp=open_file(unchangeddata, "rb"))
	  || !(p2fp=open_file(phase2data, "rb"))
	  || (compress && !(mzp=gzopen_file(manifesttmp, comp_level(cconf))))
          || (!compress && !(mp=open_file(manifesttmp, "wb"))))
	{
		close_fp(&ucfp);
		gzclose_fp(&mzp);
		close_fp(&p2fp);
		close_fp(&mp);
		free(manifesttmp);
		return -1;
	}

	init_sbufl(&ucb);
	init_sbufl(&p2b);

	while(ucfp || p2fp)
	{
		if(ucfp && !ucb.path && (ars=sbufl_fill(ucfp, NULL, &ucb, cntr)))
		{
			if(ars<0) { ret=-1; break; }
			// ars==1 means it ended ok.
			close_fp(&ucfp);
		}
		if(p2fp && !p2b.path && (ars=sbufl_fill(p2fp, NULL, &p2b, cntr)))
		{
			if(ars<0) { ret=-1; break; }
			// ars==1 means it ended ok.
			close_fp(&p2fp);

			// In recovery mode, only want to read to the last
			// entry in the phase 2 file.
			if(recovery) break;
		}

		if(ucb.path && !p2b.path)
		{
			write_status(client, STATUS_MERGING, ucb.path, cconf);
			if(sbufl_to_manifest(&ucb, mp, mzp)) { ret=-1; break; }
			free_sbufl(&ucb);
		}
		else if(!ucb.path && p2b.path)
		{
			write_status(client, STATUS_MERGING, p2b.path, cconf);
			if(sbufl_to_manifest(&p2b, mp, mzp)) { ret=-1; break; }
			free_sbufl(&p2b);
		}
		else if(!ucb.path && !p2b.path) 
		{
			continue;
		}
		else if(!(pcmp=sbufl_pathcmp(&ucb, &p2b)))
		{
			// They were the same - write one and free both.
			write_status(client, STATUS_MERGING, p2b.path, cconf);
			if(sbufl_to_manifest(&p2b, mp, mzp)) { ret=-1; break; }
			free_sbufl(&p2b);
			free_sbufl(&ucb);
		}
		else if(pcmp<0)
		{
			write_status(client, STATUS_MERGING, ucb.path, cconf);
			if(sbufl_to_manifest(&ucb, mp, mzp)) { ret=-1; break; }
			free_sbufl(&ucb);
		}
		else
		{
			write_status(client, STATUS_MERGING, p2b.path, cconf);
			if(sbufl_to_manifest(&p2b, mp, mzp)) { ret=-1; break; }
			free_sbufl(&p2b);
		}
	}

	free_sbufl(&ucb);
	free_sbufl(&p2b);

	close_fp(&p2fp);
	close_fp(&ucfp);
	if(close_fp(&mp))
	{
		logp("error closing %s in backup_phase3_server\n",
			manifesttmp);
		ret=-1;
	}
	if(gzclose_fp(&mzp))
	{
		logp("error gzclosing %s in backup_phase3_server\n",
			manifesttmp);
		ret=-1;
	}

	if(!ret)
	{
		if(do_rename(manifesttmp, manifest))
			ret=-1;
		else
		{
			unlink(phase2data);
			unlink(unchangeddata);
		}
	}

	free(manifesttmp);

	logp("End phase3 (merge manifests)\n");

	return ret;
}
