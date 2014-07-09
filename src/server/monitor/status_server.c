#include "include.h"

static int send_summaries_to_client(struct asfd *srfd,
	struct cstat *clist, const char *sel_client)
{
	int ret=-1;
	struct cstat *c;

	if(json_start(srfd)) return -1;

	for(c=clist; c; c=c->next)
	{
                if(!c->status && cstat_set_status(c))
			goto end;

                if(c->running_detail)
		{
			// Broken for now.
			//tosend=c->running_detail;
		}
		else if(sel_client && !strcmp(sel_client, c->name)
		  && (c->status==STATUS_IDLE
			|| c->status==STATUS_CLIENT_CRASHED
			|| c->status==STATUS_SERVER_CRASHED))
		{
			// Client not running, but asked for detail.
			// Gather a list of successful backups to talk about.
			if(cstat_set_backup_list(c)) goto end;
		}
		if(json_send_backup_list(srfd, clist, c))
			goto end;
	}

	ret=0;
end:
	if(json_end(srfd)) return -1;
	return ret;
}
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

/* FIX THIS
static int list_backup_file_name(struct asfd *srfd, const char *dir, const char *file)
{
	int ret=0;
	char *path=NULL;
	char msg[256]="";
	struct stat statp;
	if(!(path=prepend_s(dir, file)))
		return -1;
	if(lstat(path, &statp) || !S_ISREG(statp.st_mode))
		goto end; // Will return 0;
	snprintf(msg, sizeof(msg), "%s\n", file);
	ret=send_data_to_client(srfd, msg, strlen(msg));
end:
	free_w(&path);
	return ret;
}
*/

/*
static int browse_manifest(struct asfd *srfd, gzFile zp, const char *browse)
{
	int ret=0;
	int ars=0;
	char ls[1024]="";
	struct sbuf sb;
	struct cntr cntr;
	size_t blen=0;
	init_sbuf(&sb);
	if(browse) blen=strlen(browse);
	while(1)
	{
		int r;
		free_sbuf(&sb);
		if((ars=sbuf_fill(NULL, zp, &sb, &cntr)))
		{
			if(ars<0) ret=-1;
			// ars==1 means it ended ok.
			break;
		}

		if(sb.cmd!=CMD_DIRECTORY
		  && sb.cmd!=CMD_FILE
		  && sb.cmd!=CMD_ENC_FILE
		  && sb.cmd!=CMD_EFS_FILE
		  && sb.cmd!=CMD_SPECIAL
		  && !cmd_is_link(sb.cmd))
			continue;

		if((r=check_browsedir(browse, &sb.path, blen))<0)
		{
			ret=-1;
			break;
		}
		if(!r) continue;

		ls_output(ls, sb.path, &(sb.statp));

		if(send_data_to_client(srfd, ls, strlen(ls))
		  || send_data_to_client(srfd, "\n", 1))
		{
			ret=-1;
			break;
		}
	}
	free_sbuf(&sb);
	return ret;
}
*/

static int list_backup_file_contents(struct asfd *srfd,
	const char *dir, const char *file, const char *browse)
{
	return 0;
/* FIX THIS
	int ret=-1;
	size_t l=0;
	gzFile zp=NULL;
	char *path=NULL;
	char buf[256]="";
	if(!(path=prepend_s(dir, file))
	  || !(zp=gzopen_file(path, "rb")))
		goto end;

	if(send_data_to_client(srfd, "-list begin-\n", strlen("-list begin-\n")))
		goto end;

	if(!strcmp(file, "manifest.gz"))
	{
		if(browse_manifest(srfd, zp, browse?:"")) goto end;
	}
	else
	{
		while((l=gzread(zp, buf, sizeof(buf)))>0)
			if(send_data_to_client(srfd, buf, l)) goto end;
	}
	if(send_data_to_client(srfd, "-list end-\n", strlen("-list end-\n")))
		goto end;
	ret=0;
end:
	gzclose_fp(&zp);
	free_w(&path);
	return ret;
*/
}

static int list_backup_dir(struct asfd *srfd, struct cstat *cli, unsigned long bno)
{
	return 0;
/* FIX THIS
	int ret=0;
	struct bu *bu;
        struct bu *bu_list=NULL;
	if(bu_list_get_str(cli->basedir, &bu_list, 0))
		goto error;

	if(!bu_list) goto end;
	for(bu=bu_list; bu; bu=bu->next) if(bu->bno==bno) break;
	if(!bu) goto end;

	if(send_data_to_client(srfd, "-list begin-\n", strlen("-list begin-\n")))
		goto error;
	list_backup_file_name(srfd, bu->path, "manifest.gz");
	list_backup_file_name(srfd, bu->path, "log.gz");
	list_backup_file_name(srfd, bu->path, "restorelog.gz");
	list_backup_file_name(srfd, bu->path, "verifylog.gz");
	if(send_data_to_client(srfd, "-list end-\n", strlen("-list end-\n")))
		goto error;
	goto end;
error:
	ret=-1;
end:
	bu_list_free(&bu_list);
	return ret;
*/
}

static int list_backup_file(struct asfd *srfd, struct cstat *cli, unsigned long bno, const char *file, const char *browse)
{
	int ret=0;
        struct bu *bu=NULL;
        struct bu *bu_list=NULL;
	if(bu_list_get_str(cli->basedir, &bu_list, 0))
		goto error;

	if(!bu_list) goto end;
	for(bu=bu_list; bu; bu=bu->next) if(bu->bno==bno) break;
	if(!bu) goto end;
	printf("found: %s\n", bu->path);
	list_backup_file_contents(srfd, bu->path, file, browse);
	goto end;
error:
	ret=-1;
end:
	bu_list_free(&bu_list);
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
	const char *cp=NULL;
	char *client=NULL;
	char *backup=NULL;
	char *file=NULL;
	char *browse=NULL;
	unsigned long bno=0;
	struct cstat *cli=NULL;
printf("got client data: '%s'\n", srfd->rbuf->buf);

	cp=srfd->rbuf->buf;
	client=get_str(&cp, "c:", 0);
	backup=get_str(&cp, "b:", 0);
	file  =get_str(&cp, "f:", 0);
	browse=get_str(&cp, "p:", 1);
	if(browse)
	{
		free_w(&file);
		if(!(file=strdup_w("manifest.gz", __func__)))
			goto error;
		strip_trailing_slashes(&browse);
	}

	if(client)
	{
		if(!(cli=cstat_get_by_name(clist, client)))
			goto end;
	}
	if(backup)
	{
		if(!(bno=strtoul(backup, NULL, 10)))
			goto end;
	}
	if(file)
	{
		if(strcmp(file, "manifest.gz")
		  && strcmp(file, "log.gz")
		  && strcmp(file, "restorelog.gz")
		  && strcmp(file, "verifylog.gz"))
			goto end;
	}
/*
	printf("client: %s\n", client?:"");
	printf("backup: %s\n", backup?:"");
	printf("file: %s\n", file?:"");
*/
	if(client)
	{
		if(bno)
		{
			if(file || browse)
			{
			  printf("list file %s of backup %lu of client '%s'\n",
			    file, bno, client);
			  if(browse) printf("browse '%s'\n", browse);
				list_backup_file(srfd, cli, bno, file, browse);
			}
			else
			{
				printf("list backup %lu of client '%s'\n",
					bno, client);
				printf("basedir: %s\n", cli->basedir);
				list_backup_dir(srfd, cli, bno);
			}
		}
		else
		{
			//printf("detail request: %s\n", rbuf);
			if(send_summaries_to_client(srfd, clist, client))
				goto error;
		}
	}
	else
	{
		//printf("summaries request\n");
		if(send_summaries_to_client(srfd, clist, NULL))
			goto error;
	}

	goto end;
error:
	ret=-1;
end:
	free_w(&client);
	free_w(&backup);
	free_w(&file);
	free_w(&browse);
	return ret;
}

static int parse_data(struct asfd *asfd, struct cstat *clist)
{
	// Hacky to switch on whether it is using line buffering or not.
	if(asfd->linebuf) return parse_client_data(asfd, clist);
	return parse_parent_data(asfd, clist);
}

static int main_loop(struct async *as, struct conf *conf)
{
	int gotdata=0;
	struct asfd *asfd;
	struct cstat *clist=NULL;
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
			if(parse_data(asfd, clist)
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

static int setup_asfd(struct async *as, const char *desc, int *fd,
	int linebuf, struct conf *conf)
{
	struct asfd *asfd=NULL;
	if(!fd || *fd<0) return 0;
	set_non_blocking(*fd);
	if(!(asfd=asfd_alloc())
	  || asfd->init(asfd, desc, as, *fd, NULL, linebuf, conf))
		goto error;
	*fd=-1;
	as->asfd_add(as, asfd);
	return 0;
error:
	asfd_free(&asfd);
	return -1;
}

// Incoming status request.
int status_server(int *cfd, int *status_rfd, struct conf *conf)
{
	int ret=-1;
	struct async *as=NULL;

	// Need to get status information from status_rfd.
	// Need to read from cfd to find out what the client wants, and
	// therefore what status to write back to cfd.

	if(!(as=async_alloc())
	  || as->init(as, 0)
	  || setup_asfd(as, "status client socket",
		cfd, 1 /* linebuf */, conf)
	  || setup_asfd(as, "status server parent socket",
		status_rfd, 0 /* standard */, conf))
			goto end;

	ret=main_loop(as, conf);
end:
	async_asfd_free_all(&as);
	close_fd(cfd);
	close_fd(status_rfd);
	return ret;
}
