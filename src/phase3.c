#include "burp.h"
#include "prog.h"
#include "base64.h"
#include "msg.h"
#include "lock.h"
#include "handy.h"
#include "asyncio.h"
#include "counter.h"
#include "dpth.h"
#include "sbuf.h"
#include "auth_server.h"
#include "backup_server.h"
#include "current_backups_server.h"
#include "attribs.h"
#include "hash.h"
#include "phase3.h"

static char *get_next_tmp_path(const char *manifest)
{
	static char tmp[32];
	static uint64_t count=0;
	snprintf(tmp, sizeof(tmp), "%08lX", count++);
	return tmp;
}

static gzFile get_new_manifest(const char *manifest, gzFile spzp, struct config *conf)
{
	char *tmp;
	gzFile zp=NULL;
	char *man_path=NULL;
	if(!(tmp=get_next_tmp_path(manifest)))
		return NULL;

	if(!(man_path=prepend_s(manifest, tmp, sizeof(tmp)))
	  || !(zp=gzopen_file(man_path, comp_level(conf))))
	{
		if(man_path) free(man_path);
		return NULL;
	}
	gzprintf(spzp, "%s\n", tmp);
	free(man_path);
	return zp;
}

static int copy_unchanged_entry(struct sbuf **csb, struct sbuf *sb, struct blk **blk, gzFile *cmanzp, gzFile *mzp, gzFile spzp, const char *manifest, struct config *conf)
{
	static int ars;
	static char *copy;
	static int sig_count=0;

	if(!*mzp && !(*mzp=get_new_manifest(manifest, spzp, conf)))
		return -1;

	// Use the most recent stat for the new manifest.
	if(sbuf_to_manifest(sb, *mzp)) return -1;

	if(!(copy=strdup((*csb)->path)))
	{
		log_out_of_memory(__FUNCTION__);
		return -1;
	}

	while(1)
	{
		if((ars=sbuf_fill_from_gzfile(*csb,
			*cmanzp, *blk, NULL, conf))<0) return -1;
		else if(ars>0)
		{
			// Reached the end.

			sbuf_free(*csb);
			blk_free(*blk);
			*csb=NULL;
			*blk=NULL;
			gzclose_fp(cmanzp);
			//gzclose_fp(mzp);
			free(copy);
			return 0;
		}
		else
		{
			// Got something.
			if(strcmp((*csb)->path, copy))
			{
				// Found the next entry.
				free(copy);
				return 0;
			}

			if(!*mzp
			  && !(*mzp=get_new_manifest(manifest, spzp, conf)))
				break;
			// Should have the next signature.
			// Write it to the unchanged file.
			gzprintf_sig_and_path(*mzp, *blk);

			// FIX THIS: Should be checking bits on
			// blk->fingerprint, rather than a character.
			if(*((*blk)->weak)=='F') gzprintf_sig(spzp, *blk);

			if(++sig_count>SIG_MAX)
			{
				sig_count=0;
				gzclose_fp(mzp);
			}
		}
	}

	free(copy);
	return -1;
}

// This is basically backup_phase3_server() from burp1. It used to merge the
// unchanged and changed data into a single file. Now it splits the manifests
// into several files.
int phase3(const char *changed, const char *unchanged, const char *manifest, struct config *conf)
{
	int ars=0;
	int ret=1;
	int pcmp=0;
	gzFile mzp=NULL;
	gzFile chzp=NULL;
	gzFile unzp=NULL;
	gzFile spzp=NULL;
	struct sbuf *usb=NULL;
	struct sbuf *csb=NULL;
	struct blk *blk=NULL;
	char *sparse=NULL;

	logp("Start phase3\n");

	if(!(sparse=prepend_s(manifest, "sparse", strlen("sparse")))
	  || build_path_w(sparse)
	  || !(usb=sbuf_alloc())
	  || !(csb=sbuf_alloc())
	  || !(chzp=gzopen_file(changed, "rb"))
	  || !(unzp=gzopen_file(unchanged, "rb"))
	  || !(spzp=gzopen_file(sparse, "wb")))
		goto end;

	while(unzp || chzp)
	{
		if(!blk && !(blk=blk_alloc())) return -1;

		if(unzp
		  && usb
		  && !usb->path
		  && (ars=sbuf_fill_from_gzfile(usb, unzp, NULL, NULL, conf)))
		{
			if(ars<0) goto end;
			// ars==1 means it ended ok.
			gzclose_fp(&unzp);
		}

		if(chzp
		  && csb
		  && !csb->path
		  && (ars=sbuf_fill_from_gzfile(csb, chzp, NULL, NULL, conf)))
		{
			if(ars<0) goto end;
			// ars==1 means it ended ok.
			gzclose_fp(&chzp);
		}

		if((usb && usb->path) && (!csb || !csb->path))
		{
			if(copy_unchanged_entry(&usb, usb,
				&blk, &unzp, &mzp, spzp,
				manifest, conf)) goto end;
		}
		else if((!usb || !usb->path) && (csb && csb->path))
		{
			if(copy_unchanged_entry(&csb, csb,
				&blk, &chzp, &mzp, spzp,
				manifest, conf)) goto end;
		}
		else if((!usb || !usb->path) && (!csb || !(csb->path)))
		{
			continue;
		}
		else if(!(pcmp=sbuf_pathcmp(usb, csb)))
		{
			// They were the same - write one.
			if(copy_unchanged_entry(&csb, csb,
				&blk, &chzp, &mzp, spzp,
				manifest, conf)) goto end;
		}
		else if(pcmp<0)
		{
			if(copy_unchanged_entry(&usb, usb,
				&blk, &unzp, &mzp, spzp,
				manifest, conf)) goto end;
		}
		else
		{
			if(copy_unchanged_entry(&csb, csb,
				&blk, &chzp, &mzp, spzp,
				manifest, conf)) goto end;
		}
	}

	if(gzclose_fp(&mzp))
	{
		logp("Error closing %s in %s\n", manifest, __FUNCTION__);
		goto end;
	}

	ret=0;
//	unlink(changed);
//	unlink(unchanged);
	logp("End phase3\n");
end:
	gzclose_fp(&mzp);
	gzclose_fp(&chzp);
	gzclose_fp(&unzp);
	gzclose_fp(&spzp);
	sbuf_free(csb);
	sbuf_free(usb);
	blk_free(blk);
	if(sparse) free(sparse);
	return ret;
}
