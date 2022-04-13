#include "../../burp.h"
#include "../../alloc.h"
#include "../../bu.h"
#include "../../cmd.h"
#include "../../cstat.h"
#include "../../prepend.h"
#include "../../sbuf.h"
#include "../list.h"
#include "../manio.h"
#include "cache.h"
#include "json_output.h"
#include "browse.h"

static int do_browse_manifest(
	struct manio *manio, struct sbuf *sb, const char *browse)
{
	int browse_all = (browse && !strncmp(browse, "*", 1))? 1:0;
	int ret=-1;
	int ars=0;
	//char ls[1024]="";
	//struct cntr cntr;
	size_t blen=0;
	char *last_bd_match=NULL;
	if(browse) blen=strlen(browse);
	while(1)
	{
		int r;
		sbuf_free_content(sb);
		if((ars=manio_read(manio, sb)))
		{
			if(ars<0) goto end;
			// ars==1 means it ended ok.
			break;
		}

		if(sb->path.cmd!=CMD_DIRECTORY
		  && sb->path.cmd!=CMD_FILE
		  && sb->path.cmd!=CMD_ENC_FILE
		  && sb->path.cmd!=CMD_EFS_FILE
		  && sb->path.cmd!=CMD_SPECIAL
		  && !cmd_is_link(sb->path.cmd))
			continue;

		if(!browse_all) {
			if((r=check_browsedir(browse, sb, blen, &last_bd_match))<0)
				goto end;
			if(!r) continue;
		}

		if(json_from_entry(sb->path.buf, sb->link.buf, &sb->statp)) goto end;
	}

	ret=0;
end:
	free_w(&last_bd_match);
	return ret;
}

static int browse_manifest_start(struct cstat *cstat,
	struct bu *bu, const char *browse, int use_cache)
{
	int ret=-1;
	char *manifest=NULL;
	struct sbuf *sb=NULL;
	struct manio *manio=NULL;

	if(!(manifest=prepend_s(bu->path, "manifest.gz"))
	  || !(manio=manio_open(manifest, "rb"))
	  || !(sb=sbuf_alloc()))
		goto end;
	if(use_cache)
		ret=cache_load(manio, sb, cstat->name, bu->bno);
	else
		ret=do_browse_manifest(manio, sb, browse);
end:
	free_w(&manifest);
	manio_close(&manio);
	sbuf_free(&sb);
	return ret;
}

int browse_manifest(struct cstat *cstat,
	struct bu *bu, const char *browse, int use_cache)
{
	/* if browse directory is *, we dump all file entries, with full path
           we also avoid caching the whole list */
	if (browse && !strncmp(browse, "*", 1))
	{
        	use_cache = 0;
	}
	if(use_cache)
	{
		if(!cache_loaded(cstat->name, bu->bno)
		  && browse_manifest_start(cstat, bu, browse, use_cache))
			return -1;
		return cache_lookup(browse);
	}
	return browse_manifest_start(cstat, bu, browse, use_cache);
}
