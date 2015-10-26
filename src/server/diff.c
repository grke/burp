#include "../burp.h"
#include "../alloc.h"
#include "../asfd.h"
#include "../async.h"
#include "../bu.h"
#include "../conf.h"
#include "../cmd.h"
#include "../cntr.h"
#include "../log.h"
#include "../prepend.h"
#include "../sbuf.h"
#include "bu_get.h"
#include "child.h"
#include "manio.h"

static int diff_manifest(struct asfd *asfd,
	const char *fullpath, struct cntr *cntr, enum protocol protocol)
{
	int ret=0;
	struct sbuf *sb=NULL;
	struct manio *manio=NULL;
	char *manifest_dir=NULL;

	if(!(manifest_dir=prepend_s(fullpath,
		protocol==PROTO_1?"manifest.gz":"manifest"))
	  || !(manio=manio_open(manifest_dir, "rb", protocol))
	  || !(sb=sbuf_alloc(protocol)))
	{
		log_and_send_oom(asfd, __func__);
		goto error;
	}

	while(1)
	{
		sbuf_free_content(sb);

                switch(manio_read(manio, sb))
                {
                        case 0: break;
                        case 1: goto end; // Finished OK.
                        default: goto error;
                }

		if(protocol==PROTO_2 && sb->endfile.buf)
			continue;

		if(write_status(CNTR_STATUS_DIFFING, sb->path.buf, cntr))
			goto error;

		if(asfd->write(asfd, &sb->attr)
		  || asfd->write(asfd, &sb->path))
			goto error;
		if(sbuf_is_link(sb)
		  && asfd->write(asfd, &sb->link))
			goto error;
	}

error:
	ret=-1;
end:
	sbuf_free(&sb);
	free_w(&manifest_dir);
	manio_close(&manio);
	return ret;
}

static int send_backup_name_to_client(struct asfd *asfd, struct bu *bu)
{
	char msg[64]="";
	//snprintf(msg, sizeof(msg), "%s%s",
	//	bu->timestamp, bu->deletable?" (deletable)":"");
	snprintf(msg, sizeof(msg), "%s", bu->timestamp);
	return asfd->write_str(asfd, CMD_TIMESTAMP, msg);
}

int do_diff_server(struct asfd *asfd, struct sdirs *sdirs, struct cntr *cntr,
	enum protocol protocol, const char *backup)
{
	int ret=-1;
	uint8_t found=0;
	unsigned long bno=0;
	struct bu *bu=NULL;
	struct bu *bu_list=NULL;

	printf("in do_diff_server\n");

	if(bu_get_list(sdirs, &bu_list)
	  || write_status(CNTR_STATUS_DIFFING, NULL, cntr))
		goto end;

	if(backup && *backup) bno=strtoul(backup, NULL, 10);

	for(bu=bu_list; bu; bu=bu->next)
	{
		// Search or list a particular backup.
		if(backup && *backup)
		{
			if(!found
			  && (!strcmp(bu->timestamp, backup)
				|| bu->bno==bno))
			{
				found=1;
				if(send_backup_name_to_client(asfd, bu)
				  || diff_manifest(asfd, bu->path,
					cntr, protocol))
						goto end;
			}
		}
		// List the backups.
		else
		{
			found=1;
			if(send_backup_name_to_client(asfd, bu))
				goto end;
		}
	}

	if(backup && *backup && !found)
	{
		asfd->write_str(asfd, CMD_ERROR, "backup not found");
		goto end;
	}
	ret=0;
end:
	bu_list_free(&bu);
	return ret;
}
