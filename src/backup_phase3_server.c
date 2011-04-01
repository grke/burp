#include "burp.h"
#include "prog.h"
#include "msg.h"
#include "lock.h"
#include "rs_buf.h"
#include "handy.h"
#include "asyncio.h"
#include "zlibio.h"
#include "counter.h"
#include "dpth.h"
#include "sbuf.h"
#include "backup_phase3_server.h"

// Combine the phase1 and phase2 files into a new manifest.
int backup_phase3_server(const char *phase2data, const char *unchangeddata, const char *manifest, int recovery, int compress, const char *client, struct cntr *cntr)
{
	int ars=0;
	int ret=0;
	int pcmp=0;
	gzFile uczp=NULL;
	FILE *p2fp=NULL;
	FILE *mp=NULL;
	gzFile mzp=NULL;
	struct sbuf ucb;
	struct sbuf p2b;
	char *manifesttmp=NULL;

	logp("Begin phase3 (merge manifests)\n");

	if(!(manifesttmp=get_tmp_filename(manifest))) return -1;

        if(!(uczp=gzopen_file(unchangeddata, "rb"))
	  || !(p2fp=open_file(phase2data, "rb"))
	  || (compress && !(mzp=gzopen_file(manifesttmp, "wb9")))
          || (!compress && !(mp=open_file(manifesttmp, "wb"))))
	{
		gzclose_fp(&uczp);
		gzclose_fp(&mzp);
		close_fp(&p2fp);
		close_fp(&mp);
		free(manifesttmp);
		return -1;
	}

	init_sbuf(&ucb);
	init_sbuf(&p2b);

	while(uczp || p2fp)
	{
		if(uczp && !ucb.path && (ars=sbuf_fill(NULL, uczp, &ucb, cntr)))
		{
			if(ars<0) { ret=-1; break; }
			// ars==1 means it ended ok.
			gzclose_fp(&uczp);
		}
		if(p2fp && !p2b.path && (ars=sbuf_fill(p2fp, NULL, &p2b, cntr)))
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
			write_status(client, 3, ucb.path, cntr);
			if(sbuf_to_manifest(&ucb, mp, mzp)) { ret=-1; break; }
			free_sbuf(&ucb);
		}
		else if(!ucb.path && p2b.path)
		{
			write_status(client, 3, p2b.path, cntr);
			if(sbuf_to_manifest(&p2b, mp, mzp)) { ret=-1; break; }
			free_sbuf(&p2b);
		}
		else if(!ucb.path && !p2b.path) 
		{
			continue;
		}
		else if(!(pcmp=pathcmp(ucb.path, p2b.path)))
		{
			// They were the same - write one and free both.
			write_status(client, 3, p2b.path, cntr);
			if(sbuf_to_manifest(&p2b, mp, mzp)) { ret=-1; break; }
			free_sbuf(&p2b);
			free_sbuf(&ucb);
		}
		else if(pcmp<0)
		{
			write_status(client, 3, ucb.path, cntr);
			if(sbuf_to_manifest(&ucb, mp, mzp)) { ret=-1; break; }
			free_sbuf(&ucb);
		}
		else
		{
			write_status(client, 3, p2b.path, cntr);
			if(sbuf_to_manifest(&p2b, mp, mzp)) { ret=-1; break; }
			free_sbuf(&p2b);
		}
	}

	free_sbuf(&ucb);
	free_sbuf(&p2b);

	close_fp(&p2fp);
	close_fp(&mp);
	gzclose_fp(&uczp);
	gzclose_fp(&mzp);

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
