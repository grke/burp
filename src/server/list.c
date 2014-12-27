#include "include.h"

// Want to make sure that we are listening for reads too - this will let us
// exit promptly if the client was killed.
// FIX THIS: Maybe some of this should go in async.c/asfd.c.
static int read_and_write(struct asfd *asfd)
{
	if(asfd->as->read_write(asfd->as)) return -1;
	if(!asfd->rbuf->buf) return 0;
	iobuf_log_unexpected(asfd->rbuf, __func__);
	return -1;
}

static int flush_asio(struct asfd *asfd)
{
	while(asfd->writebuflen>0)
		if(read_and_write(asfd)) return -1;
	return 0;
}

static int write_wrapper(struct asfd *asfd, struct iobuf *wbuf)
{
	while(1)
	{
		switch(asfd->append_all_to_write_buffer(asfd, wbuf))
		{
			case APPEND_OK: return 0;
			case APPEND_BLOCKED: break;
			default: return -1;
		}
		if(read_and_write(asfd)) return -1;
	}
	return 0;
}

static int write_wrapper_str(struct asfd *asfd, char wcmd, const char *wsrc)
{
	static struct iobuf wbuf;
	wbuf.cmd=wcmd;
	wbuf.buf=(char *)wsrc;
	wbuf.len=strlen(wsrc);
	return write_wrapper(asfd, &wbuf);
}

int check_browsedir(const char *browsedir,
	struct sbuf *mb, size_t bdlen, char **last_bd_match)
{
	char *cp=mb->path.buf;
	char *copy=NULL;
	if(bdlen>0)
	{
		if(strncmp(browsedir, cp, bdlen))
			return 0;
		cp+=bdlen;
		if(browsedir[bdlen-1]!='/')
		{
			if(*cp!='/') return 0;
			cp++;
		}
	}
	if(*cp=='\0') return 0;
	if(!(copy=strdup_w(cp, __func__))) goto err;
	if((cp=strchr(copy, '/')))
	{
		if(bdlen==0) cp++;
		*cp='\0';

		if(!S_ISDIR(mb->statp.st_mode))
		{
			// We are faking a directory entry.
			// Make sure the directory bit is set.
			mb->statp.st_mode &= ~(S_IFMT);
			mb->statp.st_mode |= S_IFDIR;
			attribs_encode(mb);
		}
	}

	// Strip off possible trailing slash.
	if((cp=strrchr(copy, '/')) && cp>copy) *cp='\0';

	if(*last_bd_match)
	{
		if(!strcmp(*last_bd_match, copy))
		{
			// Got a duplicate match.
			free(copy);
			return 0;
		}
		free(*last_bd_match);
	}
	free(mb->path.buf);
	mb->path.buf=copy;
	if(!(*last_bd_match=strdup_w(copy, __func__)))
		goto err;
	return 1;
err:
	if(copy) free(copy);
	log_out_of_memory(__func__);
	return -1;
}

static int list_manifest(struct asfd *asfd,
	const char *fullpath, regex_t *regex,
	const char *browsedir, struct conf *conf)
{
	int ars=0;
	int ret=0;
	struct sbuf *sb=NULL;
	struct manio *manio=NULL;
	char *manifest_dir=NULL;
	char *last_bd_match=NULL;
	size_t bdlen=0;

	if(!(manifest_dir=prepend_s(fullpath,
		conf->protocol==PROTO_BURP1?"manifest.gz":"manifest"))
	  || !(manio=manio_alloc())
	  || manio_init_read(manio, manifest_dir)
	  || !(sb=sbuf_alloc(conf)))
	{
		log_and_send_oom(asfd, __func__);
		goto error;
	}
	manio_set_protocol(manio, conf->protocol);

	if(browsedir) bdlen=strlen(browsedir);

	while(1)
	{
		int show=0;

		if((ars=manio_sbuf_fill(manio, asfd, sb, NULL, NULL, conf))<0)
			goto error;
		else if(ars>0)
			goto end; // Finished OK.

		if(write_status(CNTR_STATUS_LISTING, sb->path.buf, conf))
			goto error;

		if(browsedir)
		{
			int r;
			if((r=check_browsedir(browsedir,
				sb, bdlen, &last_bd_match))<0)
					goto error;
			if(!r) continue;
			show++;
		}
		else
		{
			if(check_regex(regex, sb->path.buf))
				show++;
		}
		if(show)
		{
			if(write_wrapper(asfd, &sb->attr)
			  || write_wrapper(asfd, &sb->path))
				goto error;
			if(sbuf_is_link(sb)
			  && write_wrapper(asfd, &sb->link))
				goto error;
		}

		sbuf_free_content(sb);
	}

error:
	ret=-1;
end:
	sbuf_free(&sb);
	free_w(&manifest_dir);
	manio_free(&manio);
	free_w(&last_bd_match);
	return ret;
}

static int send_backup_name_to_client(struct asfd *asfd,
	struct bu *bu, struct conf *conf)
{
	char msg[64]="";
	snprintf(msg, sizeof(msg), "%s%s",
		bu->timestamp,
		// Burp2 backups are all deletable, so do not mention it.
		conf->protocol==PROTO_BURP1
		&& (bu->flags & BU_DELETABLE)?" (deletable)":"");
	return write_wrapper_str(asfd, CMD_TIMESTAMP, msg);
}

int do_list_server(struct asfd *asfd, struct sdirs *sdirs, struct conf *conf,
	const char *backup, const char *listregex, const char *browsedir)
{
	int ret=-1;
	uint8_t found=0;
	unsigned long bno=0;
	regex_t *regex=NULL;
	struct bu *bu=NULL;
	struct bu *bu_list=NULL;

	printf("in do_list_server\n");

	if(compile_regex(&regex, listregex)
	  || bu_get_list(sdirs, &bu_list)
	  || write_status(CNTR_STATUS_LISTING, NULL, conf))
		goto end;

	if(backup && *backup) bno=strtoul(backup, NULL, 10);

	for(bu=bu_list; bu; bu=bu->next)
	{
		// Search all backups for things matching the regex.
		if(listregex && backup && *backup=='a')
		{
			found=1;
			if(write_wrapper_str(asfd,
				CMD_TIMESTAMP, bu->timestamp)
			  || list_manifest(asfd, bu->path,
				regex, browsedir, conf)) goto end;
		}
		// Search or list a particular backup.
		else if(backup && *backup)
		{
			if(!found
			  && (!strcmp(bu->timestamp, backup)
				|| bu->bno==bno))
			{
				found=1;
				if(send_backup_name_to_client(asfd, bu, conf)
				  || list_manifest(asfd, bu->path, regex,
					browsedir, conf)) goto end;
			}
		}
		// List the backups.
		else
		{
			found=1;
			if(send_backup_name_to_client(asfd, bu, conf))
				goto end;
		}
	}

	if(backup && *backup && !found)
	{
		write_wrapper_str(asfd, CMD_ERROR, "backup not found");
		goto end;
	}

	if(flush_asio(asfd)) goto end;
	
	ret=0;
end:
	if(regex) { regfree(regex); free(regex); }
	bu_list_free(&bu);
	return ret;
}
