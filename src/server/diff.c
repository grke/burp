#include "../burp.h"
#include "../alloc.h"
#include "../asfd.h"
#include "../async.h"
#include "../bu.h"
#include "../conf.h"
#include "../cmd.h"
#include "../cntr.h"
#include "../cstat.h"
#include "../log.h"
#include "../prepend.h"
#include "../sbuf.h"
#include "bu_get.h"
#include "child.h"
#include "manio.h"
#include "diff.h"

static char *get_manifest_path(const char *fullpath, enum protocol protocol)
{
	return prepend_s(fullpath, protocol==PROTO_1?"manifest.gz":"manifest");
}

static int send_diff(struct asfd *asfd, const char *symbol, struct sbuf *sb)
{
	int ret=-1;
	char *dpath=NULL;
	if(!(dpath=prepend_s(symbol, sb->path.buf))
	  || asfd->write(asfd, &sb->attr)
	  || asfd->write_str(asfd, sb->path.cmd, dpath))
		goto end;
	if(sbuf_is_link(sb)
	  && asfd->write(asfd, &sb->link))
		goto end;
	ret=0;
end:
	free_w(&dpath);
	return ret;
}

static int send_deletion(struct asfd *asfd, struct sbuf *sb)
{
	return send_diff(asfd, "- ", sb);
}

static int send_addition(struct asfd *asfd, struct sbuf *sb)
{
	return send_diff(asfd, "+ ", sb);
}

static int diff_manifests(struct asfd *asfd, const char *fullpath1,
	const char *fullpath2, enum protocol protocol)
{
	int ret=-1;
	int pcmp;
	struct sbuf *sb1=NULL;
	struct sbuf *sb2=NULL;
	struct manio *manio1=NULL;
	struct manio *manio2=NULL;
	char *manifest_dir1=NULL;
	char *manifest_dir2=NULL;

	if(!(manifest_dir1=get_manifest_path(fullpath1, protocol))
	  || !(manifest_dir2=get_manifest_path(fullpath2, protocol))
	  || !(manio1=manio_open(manifest_dir1, "rb", protocol))
	  || !(manio2=manio_open(manifest_dir2, "rb", protocol))
	  || !(sb1=sbuf_alloc(protocol))
	  || !(sb2=sbuf_alloc(protocol)))
	{
		log_and_send_oom(asfd);
		goto end;
	}

	while(manio1 || manio2)
	{
		if(manio1
		  && !sb1->path.buf)
		{
			switch(manio_read(manio1, sb1))
			{
				case -1: goto end;
				case 1: manio_close(&manio1);
			}
		}

		if(manio2
		  && !sb2->path.buf)
		{
			switch(manio_read(manio2, sb2))
			{
				case -1: goto end;
				case 1: manio_close(&manio2);
			}
		}

		if(sb1->path.buf && !sb2->path.buf)
		{
			if(send_deletion(asfd, sb1))
				goto end;
			sbuf_free_content(sb1);
		}
		else if(!sb1->path.buf && sb2->path.buf)
		{
			if(send_addition(asfd, sb2))
				goto end;
			sbuf_free_content(sb2);
		}
		else if(!sb1->path.buf && !sb2->path.buf)
		{
			continue;
		}
		else if(!(pcmp=sbuf_pathcmp(sb1, sb2)))
		{
			if(sb1->statp.st_mtime!=sb2->statp.st_mtime)
			{
				if(send_deletion(asfd, sb1)
				  || send_addition(asfd, sb2))
					goto end;
			}
			sbuf_free_content(sb1);
			sbuf_free_content(sb2);
		}
		else if(pcmp<0)
		{
			if(send_deletion(asfd, sb1))
				goto end;
			sbuf_free_content(sb1);
		}
		else
		{
			if(send_addition(asfd, sb2))
				goto end;
			sbuf_free_content(sb2);
		}
	}

	ret=0;
end:
	sbuf_free(&sb1);
	sbuf_free(&sb2);
	free_w(&manifest_dir1);
	free_w(&manifest_dir2);
	manio_close(&manio1);
	manio_close(&manio2);
	return ret;
}

static int send_backup_name_to_client(struct asfd *asfd, struct bu *bu)
{
	char msg[64]="";
	snprintf(msg, sizeof(msg), "%s", bu->timestamp);
	return asfd->write_str(asfd, CMD_TIMESTAMP, msg);
}

int do_diff_server(struct asfd *asfd, struct sdirs *sdirs, struct conf **confs,
	enum protocol protocol, const char *backup1, const char *backup2)
{
	int ret=-1;
	unsigned long bno1=0;
	unsigned long bno2=0;
	struct bu *bu1=NULL;
	struct bu *bu2=NULL;
	struct bu *bu_list=NULL;
	struct cntr *cntr=NULL;

	if(confs)
		cntr=get_cntr(confs);

	//printf("in do_diff_server\n");

	if(bu_get_list(sdirs, &bu_list))
		goto end;

	if(backup2 && *backup2)
		bno2=strtoul(backup2, NULL, 10);
	if(backup1 && *backup1)
		bno1=strtoul(backup1, NULL, 10);

	if(!bno1 || !bno2 || bno1==bno2)
	{
		asfd->write_str(asfd, CMD_ERROR,
			"you need to specify two backups");
		goto end;
	}

	for(bu1=bu_list; bu1; bu1=bu1->next)
		if(bu1->bno==bno1) break;
	for(bu2=bu_list; bu2; bu2=bu2->next)
		if(bu2->bno==bno2) break;
	if(!bu1 || !bu2)
	{
		asfd->write_str(asfd, CMD_ERROR,
			"could not find specified backups");
		goto end;
	}

	if(send_backup_name_to_client(asfd, bu1)
	  || send_backup_name_to_client(asfd, bu2))
		goto end;

	cntr->bno=(int)bu2->bno;
	if(timed_operation_status_only(CNTR_STATUS_DIFFING, NULL, confs))
		goto end;

	if(diff_manifests(asfd, bu1->path, bu2->path, protocol))
		goto end;

	ret=0;
end:
	bu_list_free(&bu_list);
	return ret;
}
