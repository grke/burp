#include "../../burp.h"
#include "../../alloc.h"
#include "../../asfd.h"
#include "../../async.h"
#include "../../bu.h"
#include "../../cstat.h"
#include "../../handy.h"
#include "../../iobuf.h"
#include "../../log.h"
#include "cstat.h"
#include "json_output.h"
#include "status_server.h"

#ifndef UTEST
static
#endif
int extract_client_and_pid(char *buf, char **cname, int *pid)
{
	char *cp=NULL;
	char *pp=NULL;

	// Extract the client name.
	if((cp=strchr(buf, '\t')))
		*cp='\0';
	if(!(*cname=strdup_w(buf, __func__)))
		return -1;
	if(cp)
		*cp='\t';

	// Extract the pid.
	if((pp=strrchr(*cname, '.')))
	{
		*pp='\0';
		*pid=atoi(pp+1);
	}
	return 0;
}

static int parse_cntr_data(const char *buf, struct cstat *clist)
{
	int ret=-1;
	char *cname=NULL;
	struct cstat *c=NULL;
	char *path=NULL;
	char *dp=NULL;
	int pid=-1;

	// Skip the type.
	if(!(dp=strchr(buf, '\t')))
		return 0;
	dp++;

	if(extract_client_and_pid(dp, &cname, &pid))
		return -1;
	if(!cname)
		return 0;

	// Find the array entry for this client,
	// and add the detail from the parent to it.
	for(c=clist; c; c=c->next)
	{
		if(strcmp(c->name, cname))
			continue;
		cstat_set_run_status(c, RUN_STATUS_RUNNING);
		if(str_to_cntr(buf, c, &path))
			goto end;
	}

// FIX THIS: Do something with path.

	ret=0;
end:
	free_w(&cname);
	free_w(&path);
	return ret;
}

static int parse_clients_list(char *buf, struct cstat *clist)
{
	char *tok=NULL;
	struct cstat *c;

	// Do not need the first token.
	if(!(tok=strtok(buf, "\t\n")))
		return 0;
	for(c=clist; c; c=c->next)
		cstat_set_run_status(c, RUN_STATUS_IDLE);

	while((tok=strtok(NULL, "\t\n")))
	{
		int pid=-1;
		char *cname=NULL;
		if(extract_client_and_pid(tok, &cname, &pid))
			return -1;
		for(c=clist; c; c=c->next)
		{
			if(strcmp(c->name, cname))
				continue;
			cstat_set_run_status(c, RUN_STATUS_RUNNING);
			break;
		}
		free_w(&cname);
	}

	return 0;
}

#ifndef UTEST
static
#endif
int parse_parent_data(char *buf, struct cstat *clist)
{
	if(!buf || !*buf)
		return 0;
//printf("got parent data: '%s'\n", buf);

	if(!strncmp(buf, "cntr", strlen("cntr")))
	{
		if(parse_cntr_data(buf, clist))
			return -1;
	}
	else if(!strncmp(buf, "clients", strlen("clients")))
	{
		if(parse_clients_list(buf, clist))
			return -1;
	}

	return 0;
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

/*
void dump_cbno(struct cstat *clist, const char *msg)
{
	if(!clist) return;
	printf("dump %s: %s\n", msg, clist->name);
	struct bu *b;
	for(b=clist->bu; b; b=b->prev)
		printf("   %d\n", b->bno);
}
*/

static int parse_client_data(struct asfd *srfd,
	struct cstat *clist, struct conf **confs)
{
	int ret=0;
	char *command=NULL;
	char *client=NULL;
	char *backup=NULL;
	char *logfile=NULL;
	char *browse=NULL;
	const char *cp=NULL;
	struct cstat *cstat=NULL;
        struct bu *bu=NULL;
//logp("got client data: '%s'\n", srfd->rbuf->buf);

	cp=srfd->rbuf->buf;

	command=get_str(&cp, "j:", 0);
	client=get_str(&cp, "c:", 0);
	backup=get_str(&cp, "b:", 0);
	logfile=get_str(&cp, "l:", 0);
	browse=get_str(&cp, "p:", 1);

	if(command)
	{
		if(!strcmp(command, "pretty-print-on"))
		{
			json_set_pretty_print(1);
			if(json_send_warn(srfd, "Pretty print on"))
				goto error;
		}
		else if(!strcmp(command, "pretty-print-off"))
		{
			json_set_pretty_print(0);
			if(json_send_warn(srfd, "Pretty print off"))
				goto error;
		}
		else
		{
			if(json_send_warn(srfd, "Unknown command"))
				goto error;
		}
		goto end;
	}

	if(browse)
	{
		free_w(&logfile);
		if(!(logfile=strdup_w("manifest", __func__)))
			goto error;
		strip_trailing_slashes(&browse);
	}

//dump_cbno(clist, "pcd");

	if(client && *client)
	{
		if(!(cstat=cstat_get_by_name(clist, client)))
		{
			char msg[256]="";
			snprintf(msg, sizeof(msg),
				"Could not find client: %s", client);
			if(json_send_warn(srfd, msg))
				goto error;
			goto end;
		}

		if(cstat_set_backup_list(cstat))
		{
			if(json_send_warn(srfd, "Could not get backup list"))
				goto error;
			goto end;
			
		}
	}
	if(cstat && backup)
	{
		unsigned long bno=0;
		if(!(bno=strtoul(backup, NULL, 10)))
		{
			if(json_send_warn(srfd, "Could not get backup number"))
				goto error;
			goto end;
		}
		for(bu=cstat->bu; bu; bu=bu->prev)
			if(bu->bno==bno) break;

		if(!bu)
		{
			if(json_send_warn(srfd, "Backup not found"))
				goto error;
			goto end;
		}
	}
	if(logfile)
	{
		if(strcmp(logfile, "manifest")
		  && strcmp(logfile, "backup")
		  && strcmp(logfile, "restore")
		  && strcmp(logfile, "verify")
		  && strcmp(logfile, "backup_stats")
		  && strcmp(logfile, "restore_stats")
		  && strcmp(logfile, "verify_stats"))
		{
			if(json_send_warn(srfd, "File not supported"))
				goto error;
			goto end;
		}
	}
/*
	printf("client: %s\n", client?:"");
	printf("backup: %s\n", backup?:"");
	printf("logfile: %s\n", logfile?:"");
*/

	if(json_send(srfd, clist, cstat, bu, logfile, browse,
		get_int(confs[OPT_MONITOR_BROWSE_CACHE])))
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

static int parse_data(struct asfd *asfd, struct cstat *clist,
	struct asfd *cfd, struct conf **confs)
{
	if(asfd==cfd) return parse_client_data(asfd, clist, confs);
	return parse_parent_data(asfd->rbuf->buf, clist);
}

static int have_data_for_running_clients(struct cstat *clist)
{
	struct cstat *c;
	for(c=clist; c; c=c->next)
		if(c->run_status==RUN_STATUS_RUNNING
		  && c->cntr->cntr_status==CNTR_STATUS_UNSET)
			return 0;
	return 1;
}

static int have_run_statuses(struct cstat *clist)
{
	struct cstat *c;
	for(c=clist; c; c=c->next)
		if(c->permitted && c->run_status==RUN_STATUS_UNSET)
			return 0;
	return 1;
}

static int get_initial_data(struct async *as,
	struct cstat **clist,
	struct conf **confs, struct conf **cconfs)
{
	int x=10;
	struct asfd *asfd=NULL;

	if(cstat_load_data_from_disk(clist, confs, cconfs))
		return -1;

	// Try to get the initial data.
	while(x)
	{
		// Do not wait forever for running clients.
		if(!have_data_for_running_clients(*clist))
			x--;
		else if(have_run_statuses(*clist))
			return 0;

		if(as->read_write(as))
		{
			logp("Exiting main status server loop\n");
			return -1;
		}
		asfd=as->asfd->next;
		if(asfd->rbuf->buf)
		{
			if(parse_data(asfd, *clist, NULL, confs))
			{
				iobuf_free_content(asfd->rbuf);
				return -1;
			}
			iobuf_free_content(asfd->rbuf);
		}
	}
	return 0;
}

int status_server(struct async *as, struct conf **confs)
{
	int ret=-1;
	int gotdata=0;
	struct asfd *asfd;
	struct cstat *clist=NULL;
	struct asfd *cfd=as->asfd; // Client.
	struct conf **cconfs=NULL;

	if(!(cconfs=confs_alloc()))
		goto end;

	if(get_initial_data(as, &clist, confs, cconfs))
		goto end;

	while(1)
	{
		// Take the opportunity to get data from the disk if nothing
		// was read from the fds.
		if(gotdata) gotdata=0;
		else if(cstat_load_data_from_disk(&clist, confs, cconfs))
			goto end;
		if(as->read_write(as))
		{
			logp("Exiting main status server loop\n");
			break;
		}
		for(asfd=as->asfd; asfd; asfd=asfd->next)
			while(asfd->rbuf->buf)
		{
			gotdata=1;
			if(parse_data(asfd, clist, cfd, confs)
			  || asfd->parse_readbuf(asfd))
				goto end;
			iobuf_free_content(asfd->rbuf);
		}
	}
	ret=0;
end:
// FIX THIS: should free clist;
	return ret;
}
