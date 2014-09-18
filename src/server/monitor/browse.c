#include "include.h"

static int do_browse_manifest(struct asfd *srfd, gzFile zp,
	struct manio *manio, struct sbuf *sb, const char *browse)
{
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
		if((ars=manio_sbuf_fill(manio, NULL, sb, NULL, NULL, NULL)))
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

		if((r=check_browsedir(browse, &(sb->path.buf),
		  blen, &last_bd_match))<0)
			goto end;
		if(!r) continue;

		if(json_from_sbuf(sb)) goto end;
	}

	ret=0;
end:
	free_w(&last_bd_match);
	return ret;
}

int browse_manifest(struct asfd *srfd, struct cstat *cstat,
	struct bu *bu, const char *browse)
{
	int ret=-1;
	gzFile zp=NULL;
	char *manifest=NULL;
	struct sbuf *sb=NULL;
	struct manio *manio=NULL;

	if(!(manifest=prepend_s(bu->path,
		cstat->protocol==PROTO_BURP1?"manifest.gz":"manifest"))
	  || !(manio=manio_alloc())
	  || manio_init_read(manio, manifest)
	  || !(sb=sbuf_alloc_protocol(cstat->protocol)))
		goto end;
	manio_set_protocol(manio, cstat->protocol);
	ret=do_browse_manifest(srfd, zp, manio, sb, browse);
end:
	gzclose_fp(&zp);
	free_w(&manifest);
	manio_free(&manio);
	sbuf_free(&sb);
	return ret;
}
