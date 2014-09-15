#include "include.h"

/*
static int send_detail_to_client(struct asfd *srfd, struct cstat **clist, int clen, const char *name)
{
	int q=0;
	for(q=0; q<clen; q++)
	{
		if(clist[q]->name && !strcmp(clist[q]->name, name))
		{
			char *tosend=NULL;
			if(clist[q]->running_detail)
				tosend=clist[q]->running_detail;
			else
				tosend=clist[q]->summary;
			if(send_data_to_client(srfd, tosend, strlen(tosend)))
				return -1;
			break;
		}
	}
	return 0;
}
*/


static int parse_parent_data_entry(char *tok, struct cstat *clist)
{
	char *tp=NULL;
	struct cstat *c;
	//logp("status server got: %s", tok);

	// Find the array entry for this client,
	// and add the detail from the parent to it.
	// The name of the client is at the start, and
	// the fields are tab separated.
	if(!(tp=strchr(tok, '\t'))) return 0;
	*tp='\0';
	for(c=clist; c; c=c->next)
	{
		if(!strcmp(c->name, tok))
		{
			int x=0;
			*tp='\t'; // put the tab back.
			x=strlen(tok);
			free_w(&c->running_detail);
			//clist[q]->running_detail=strdup_w(tok, __func__);

			// Need to add the newline back on the end.
			if(!(c->running_detail=(char *)malloc_w(x+2, __func__)))
				return -1;
			snprintf(c->running_detail, x+2, "%s\n", tok);
			
		}
	}
	return 0;
}

static int parse_parent_data(struct asfd *asfd, struct cstat *clist)
{
	int ret=-1;
	char *tok=NULL;
	char *copyall=NULL;
printf("got parent data: '%s'\n", asfd->rbuf->buf);

	if(!(copyall=strdup_w(asfd->rbuf->buf, __func__)))
		goto end;

	if((tok=strtok(copyall, "\n")))
	{
printf("got tok: %s\n", tok);
		if(parse_parent_data_entry(tok, clist)) goto end;
		while((tok=strtok(NULL, "\n")))
			if(parse_parent_data_entry(tok, clist))
				goto end;
	}

	ret=0;
end:
	free_w(&copyall);
	return ret;
}

static int browse_manifest(struct asfd *srfd, gzFile zp,
	struct manio *manio, struct sbuf *sb, const char *browse)
{
	int ret=0;
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
			if(ars<0) ret=-1;
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
				return -1;
		if(!r) continue;

/*
		printf("%s\n", sb->path.buf);
		ls_output(ls, sb.path, &(sb.statp));

		if(send_data_to_client(srfd, ls, strlen(ls))
		  || send_data_to_client(srfd, "\n", 1))
			return -1;
*/
	}
	free_w(&last_bd_match);
	return ret;
}

static int browse_manifest_w(struct asfd *srfd, struct cstat *cstat,
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
	ret=browse_manifest(srfd, zp, manio, sb, browse);
end:
	gzclose_fp(&zp);
	free_w(&manifest);
	manio_free(&manio);
	sbuf_free(&sb);
	return ret;
}

static char *get_str(const char **buf, const char *pre, int last)
{
	size_t len=0;
	char *cp=NULL;
	char *copy=NULL;
	char *ret=NULL;
	if(!buf || !*buf) goto end;
	len=strlen(pre);
	if(strncmp(*buf, pre, len)
	  || !(copy=strdup_w((*buf)+len, __func__)))
		goto end;
	if(!last && (cp=strchr(copy, ':'))) *cp='\0';
	*buf+=len+strlen(copy)+1;
	ret=strdup_w(copy, __func__);
end:
	free_w(&copy);
	return ret;
}

static int parse_client_data(struct asfd *srfd, struct cstat *clist)
{
	int ret=0;
	char *client=NULL;
	char *backup=NULL;
	char *logfile=NULL;
	char *browse=NULL;
	const char *cp=NULL;
	struct cstat *cstat=NULL;
        struct bu *bu=NULL;
printf("got client data: '%s'\n", srfd->rbuf->buf);

	cp=srfd->rbuf->buf;
	client=get_str(&cp, "c:", 0);
	backup=get_str(&cp, "b:", 0);
	logfile=get_str(&cp, "l:", 0);
	browse=get_str(&cp, "p:", 1);
	if(browse)
	{
		free_w(&logfile);
		if(!(logfile=strdup_w("manifest", __func__)))
			goto error;
		strip_trailing_slashes(&browse);
	}

	if(client)
	{
		if(!(cstat=cstat_get_by_name(clist, client)))
			goto end;

		if(cstat_set_backup_list(cstat)) goto end;
	}
	if(cstat && backup)
	{
		unsigned long bno=0;
		if(!(bno=strtoul(backup, NULL, 10)))
			goto end;
		for(bu=cstat->bu; bu; bu=bu->prev)
			if(bu->bno==bno) break;

		if(!bu) goto end;
	}
	if(logfile)
	{
		if(strcmp(logfile, "manifest")
		  && strcmp(logfile, "backup")
		  && strcmp(logfile, "restore")
		  && strcmp(logfile, "verify"))
			goto end;
	}

	printf("client: %s\n", client?:"");
	printf("backup: %s\n", backup?:"");
	printf("logfile: %s\n", logfile?:"");

	if(browse)
	{
		if(browse_manifest_w(srfd, cstat, bu, browse))
			goto error;
		goto end;
	}

	if(cstat)
	{
		if(!cstat->status && cstat_set_status(cstat))
			goto error;
	}
	else for(cstat=clist; cstat; cstat=cstat->next)
	{
		if(!cstat->status && cstat_set_status(cstat))
			goto error;
	}

	if(json_send(srfd, clist, cstat, bu, logfile))
		goto error;

	goto end;
error:
	ret=-1;
end:
	free_w(&client);
	free_w(&backup);
	free_w(&logfile);
	free_w(&browse);
	return ret;
}

static int parse_data(struct asfd *asfd, struct cstat *clist, struct asfd *cfd)
{
	if(asfd==cfd) return parse_client_data(asfd, clist);
	return parse_parent_data(asfd, clist);
}

int status_server(struct async *as, struct conf *conf)
{
	int gotdata=0;
	struct asfd *asfd;
	struct cstat *clist=NULL;
	struct asfd *cfd=as->asfd; // Client.
	while(1)
	{
		// Take the opportunity to get data from the disk if nothing
		// was read from the fds.
		if(gotdata) gotdata=0;
		else if(cstat_load_data_from_disk(&clist, conf))
			goto error;
		if(as->read_write(as))
		{
			logp("Exiting main status server loop\n");
			break;
		}
		for(asfd=as->asfd; asfd; asfd=asfd->next)
			while(asfd->rbuf->buf)
		{
			gotdata=1;
			if(parse_data(asfd, clist, cfd)
			  || asfd->parse_readbuf(asfd))
				goto error;
			iobuf_free_content(asfd->rbuf);
		}
	}
// FIX THIS: should free clist;
	return 0;
error:
	return -1;
}
