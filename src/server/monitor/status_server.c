#include "../../burp.h"
#include "../../alloc.h"
#include "../../asfd.h"
#include "../../async.h"
#include "../../bu.h"
#include "../../cstat.h"
#include "../../conffile.h"
#include "../../handy.h"
#include "../../iobuf.h"
#include "../../log.h"
#include "cstat.h"
#include "json_output.h"
#include "status_server.h"

static int parse_cntr_data(const char *buf, struct cstat *clist)
{
	int bno=0;
	int ret=-1;
	char *cname=NULL;
	struct cstat *c=NULL;
	char *path=NULL;
	char *dp=NULL;
	pid_t pid=-1;

	// Skip the type.
	if(!(dp=strchr(buf, '\t')))
		return 0;
	dp++;

	if(extract_client_pid_bno(dp, &cname, &pid, &bno))
		return -1;
	if(!cname)
		return 0;

	// Find the array entry for this client,
	// and add the detail from the parent to it.
	for(c=clist; c; c=c->next)
	{
		struct cntr *cntr=NULL;
		if(strcmp(c->name, cname))
			continue;
		cstat_set_run_status(c, RUN_STATUS_RUNNING);

		// Find the cntr entry for this client/pid.
		for(cntr=c->cntrs; cntr; cntr=cntr->next)
			if(cntr->pid==pid)
				break;
		if(!cntr)
		{
			// Need to allocate a new cntr.
			if(!(cntr=cntr_alloc())
			  || cntr_init(cntr, cname, pid))
				goto end;
			cstat_add_cntr_to_list(c, cntr);
		}
		if(str_to_cntr(buf, cntr, &path))
			goto end;
	}

// FIX THIS: Do something with path.

	ret=0;
end:
	free_w(&cname);
	free_w(&path);
	return ret;
}

static void clean_up_cntrs(struct cstat *clist)
{
	struct cstat *c;
	for(c=clist; c; c=c->next)
	{
		struct cntr *cntr=NULL;
		for(cntr=c->cntrs; cntr; )
		{
			if(cntr->found)
			{
				cntr=cntr->next;
				continue;
			}
			cstat_remove_cntr_from_list(c, cntr);
			cntr_free(&cntr);
			if(c->cntrs)
				cntr=c->cntrs;
		}
	}
}

static int parse_clients_list(char *buf, struct cstat *clist)
{
	char *tok=NULL;
	struct cstat *c;

	if(!clist)
		return 0;

	// Do not need the first token.
	if(!(tok=strtok(buf, "\t\n")))
		return 0;
	for(c=clist; c; c=c->next)
	{
		struct cntr *cntr;
		for(cntr=c->cntrs; cntr; cntr=cntr->next)
			cntr->found=0;
		cstat_set_run_status(c, RUN_STATUS_IDLE);
	}

	while((tok=strtok(NULL, "\t\n")))
	{
		int bno=0;
		pid_t pid=-1;
		char *cname=NULL;
		if(extract_client_pid_bno(tok, &cname, &pid, &bno))
			return -1;
		for(c=clist; c; c=c->next)
		{
			struct cntr *cntr;
			if(strcmp(c->name, cname))
				continue;
			cstat_set_run_status(c, RUN_STATUS_RUNNING);
			for(cntr=c->cntrs; cntr; cntr=cntr->next)
				if(cntr->pid==pid)
					break;
			if(cntr)
			{
				cntr->found=1;
				cntr->bno=bno;
			}
			break;
		}
		free_w(&cname);
	}

	clean_up_cntrs(clist);

	return 0;
}

#ifndef UTEST
static
#endif
int parse_parent_data(char *buf, struct cstat *clist)
{
	if(!buf || !*buf)
		return 0;

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

#ifndef UTEST
static
#endif
int status_server_parse_cmd(
	const char *buf,
	char **command,
	char **client,
	char **backup,
	char **logfile,
	char **browse
) {
	int ret=-1;
	char *tok=NULL;
	char **current=NULL;
	char *copy=NULL;

	if(!buf)
		return 0;

	if(!(copy=strdup_w(buf, __func__)))
		goto end;
	if(!(tok=strtok(copy, ":")))
	{
		ret=0;
		goto end;
	}
	do {
		if(current)
		{
			if(!(*current=strdup_w(tok, __func__)))
				goto end;
			current=NULL;
		}
		else
		{
			if(!strcmp(tok, "j"))
				current=command;
			else if(!strcmp(tok, "c"))
				current=client;
			else if(!strcmp(tok, "b"))
				current=backup;
			else if(!strcmp(tok, "l"))
				current=logfile;
			else if(!strcmp(tok, "p"))
			{
				// The path may have colons in it. So, make
				// this the last one.
				if(copy+strlen(buf) > tok+1)
				{
					if(!(*browse=strdup_w(tok+2, __func__)))
						goto end;
				}
				break;
			}
			else
				current=NULL;
		}
	} while((tok=strtok(NULL, ":")));

	ret=0;
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

static int response_marker_start(struct asfd *srfd, const char *buf)
{
	return json_send_msg(srfd, "response-start", buf);
}

static int response_marker_end(struct asfd *srfd, const char *buf)
{
	return json_send_msg(srfd, "response-end", buf);
}

static int parse_client_data(struct asfd *srfd,
	struct cstat *clist, int monitor_browse_cache, long *peer_version)
{
	int ret=0;
	char *command=NULL;
	char *client=NULL;
	char *backup=NULL;
	char *logfile=NULL;
	char *browse=NULL;
	struct cstat *cstat=NULL;
        struct bu *bu=NULL;
	static int response_markers=0;
	const char *cmd_result=NULL;
//logp("got client data: '%s'\n", srfd->rbuf->buf);

	if(status_server_parse_cmd(
		srfd->rbuf->buf,
		&command,
		&client,
		&backup,
		&logfile,
		&browse))
			goto error;

	if(command)
	{
		size_t l;
		char peer_version_str[32]="peer_version=";
		l=strlen(peer_version_str);
		if(!strcmp(command, "pretty-print-on"))
		{
			json_set_pretty_print(1);
			cmd_result="Pretty print on";
		}
		else if(!strcmp(command, "pretty-print-off"))
		{
			json_set_pretty_print(0);
			cmd_result="Pretty print off";
		}
		else if(!strcmp(command, "response-markers-on"))
		{
			response_markers=1;
			cmd_result="Response markers on";
		}
		else if(!strcmp(command, "response-markers-off"))
		{
			response_markers=0;
			cmd_result="Response markers off";
		}
		else if(!strncmp(command, peer_version_str, l))
		{
			if(!(*peer_version=version_to_long(command+l)))
				goto error;
			cmd_result="Peer version updated";
		}
		else
		{
			cmd_result="Unknown command";
		}
	}

	if(response_markers
	  && response_marker_start(srfd, srfd->rbuf->buf))
		goto error;

	if(cmd_result)
	{
		if(json_send_warn(srfd, cmd_result))
			goto error;
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
		monitor_browse_cache, *peer_version))
			goto error;

	goto end;
error:
	ret=-1;
end:
	if(response_markers
	  && response_marker_end(srfd, srfd->rbuf->buf))
		ret=-1;

	free_w(&client);
	free_w(&backup);
	free_w(&logfile);
	free_w(&browse);
	return ret;
}

static int parse_data(struct asfd *asfd, struct cstat *clist,
	struct asfd *cfd, int monitor_browse_cache, long *peer_version)
{
	if(asfd==cfd)
		return parse_client_data(asfd,
			clist, monitor_browse_cache, peer_version);
	return parse_parent_data(asfd->rbuf->buf, clist);
}

static int have_data_for_running_clients(struct cstat *clist)
{
	struct cstat *c;
	for(c=clist; c; c=c->next)
	{
		if(c->run_status==RUN_STATUS_RUNNING)
		{
			if(!c->cntrs
			  || c->cntrs->cntr_status==CNTR_STATUS_UNSET)
				return 0;
		}
	}
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
	struct conf **monitor_cconfs,
	struct conf **globalcs, struct conf **cconfs,
	int monitor_browse_cache, long *peer_version)
{
	int x=10;
	struct asfd *asfd=NULL;

	if(cstat_load_data_from_disk(clist, monitor_cconfs, globalcs, cconfs))
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
			if(parse_data(asfd, *clist,
				NULL, monitor_browse_cache, peer_version))
			{
				iobuf_free_content(asfd->rbuf);
				return -1;
			}
			iobuf_free_content(asfd->rbuf);
		}
	}
	return 0;
}

int status_server(struct async *as, struct conf **monitor_cconfs)
{
	int ret=-1;
	int gotdata=0;
	struct asfd *asfd;
	struct cstat *clist=NULL;
	struct asfd *cfd=as->asfd; // Client.
	struct conf **cconfs=NULL;
	struct conf **globalcs=NULL;
	const char *conffile=get_string(monitor_cconfs[OPT_CONFFILE]);
	long peer_version=version_to_long(get_string(monitor_cconfs[OPT_PEER_VERSION]));
	int monitor_browse_cache=get_int(monitor_cconfs[OPT_MONITOR_BROWSE_CACHE]);

	// We need to load a fresh global conf so that the clients do not all
	// get settings from the monitor client. In particular, if protocol=0
	// in both burp-server.conf and the monitor burp.conf, the monitor
	// client gets protocol=1 from extra comms, and all the clients here
	// would end up getting protocol=1.
	if(!(globalcs=confs_alloc()))
		goto end;
	if(confs_init(globalcs)) return -1;
	if(conf_load_global_only(conffile, globalcs))
		return -1;

	if(!(cconfs=confs_alloc()))
		goto end;

	if(get_initial_data(as, &clist, monitor_cconfs,
		globalcs, cconfs, monitor_browse_cache, &peer_version))
			goto end;

	while(1)
	{
		// Take the opportunity to get data from the disk if nothing
		// was read from the fds.
		if(gotdata) gotdata=0;
		else if(cstat_load_data_from_disk(&clist, monitor_cconfs,
			globalcs, cconfs))
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
			if(parse_data(asfd, clist,
				cfd, monitor_browse_cache, &peer_version)
			  || asfd->parse_readbuf(asfd))
				goto end;
			iobuf_free_content(asfd->rbuf);
		}
	}
	ret=0;
end:
// FIX THIS: should free clist;
	confs_free(&globalcs);
	return ret;
}
