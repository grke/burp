#include "burp.h"
#include "prog.h"
#include "msg.h"
#include "lock.h"
#include "rs_buf.h"
#include "handy.h"
#include "asyncio.h"
#include "zlibio.h"
#include "counter.h"
#include "dpth.h"
#include "sbuf.h"
#include "list_server.h"
#include "current_backups_server.h"

static int list_manifest(const char *fullpath, regex_t *regex, const char *client, struct cntr *p1cntr, struct cntr *cntr)
{
	int ars=0;
	int ret=0;
	int quit=0;
	gzFile fp=NULL;
	struct sbuf mb;
	char *manifest=NULL;

	init_sbuf(&mb);

	if(!(manifest=prepend_s(fullpath, "manifest.gz", strlen("manifest.gz"))))
	{
		log_and_send("out of memory");
		return -1;
	}
	if(!(fp=gzopen_file(manifest, "rb")))
	{
		log_and_send("could not open manifest");
		free(manifest);
		return -1;
	}
	free(manifest);


	while(!quit)
	{
		//logp("list manifest loop\n");
		// Need to parse while sending, to take note of the regex.

		free_sbuf(&mb);
		if((ars=sbuf_fill(NULL, fp, &mb, cntr)))
		{
			if(ars<0) ret=-1;
			// ars==1 means it ended ok.
			break;
		}

		if(mb.path[mb.plen]=='\n') mb.path[mb.plen]='\0';
		write_status(client, STATUS_LISTING, mb.path, p1cntr, cntr);
		if(check_regex(regex, mb.path))
		{
			if(async_write(CMD_STAT, mb.statbuf, mb.slen)
			  || async_write(mb.cmd, mb.path, mb.plen))
			{ quit++; ret=-1; }
			else if(sbuf_is_link(&mb)
			  && async_write(mb.cmd, mb.linkto, mb.llen))
			{ quit++; ret=-1; }
		}
	}
	gzclose_fp(&fp);
	free_sbuf(&mb);
	return ret;
}

int do_list_server(const char *basedir, const char *backup, const char *listregex, const char *client, struct cntr *p1cntr, struct cntr *cntr)
{
	int a=0;
	int i=0;
	int ret=0;
	int found=0;
	struct bu *arr=NULL;
	unsigned long index=0;
	regex_t *regex=NULL;

	logp("in do_list\n");

	if(compile_regex(&regex, listregex)) return -1;

	if(get_current_backups(basedir, &arr, &a, 1))
	{
		if(regex) { regfree(regex); free(regex); }
		return -1;
	}

	write_status(client, STATUS_LISTING, NULL, p1cntr, cntr);

	if(backup && *backup) index=strtoul(backup, NULL, 10);

	for(i=0; i<a; i++)
	{
		// Search all backups for things matching the regex.
		if(listregex && backup && *backup=='a')
		{
			found=TRUE;
			async_write(CMD_TIMESTAMP,
				arr[i].timestamp, strlen(arr[i].timestamp));
			ret+=list_manifest(arr[i].path, regex, client,
				p1cntr, cntr);
		}
		// Search or list a particular backup.
		else if(backup && *backup)
		{
			if(!found
			  && (!strcmp(arr[i].timestamp, backup)
				|| arr[i].index==index))
			{
				found=TRUE;
				async_write(CMD_TIMESTAMP,
				  arr[i].timestamp, strlen(arr[i].timestamp));
				ret=list_manifest(arr[i].path, regex, client,
					p1cntr, cntr);
			}
		}
		// List the backups.
		else
		{
			found=TRUE;
			async_write(CMD_TIMESTAMP,
				arr[i].timestamp, strlen(arr[i].timestamp));
		}
	}
	free_current_backups(&arr, a);

	if(backup && *backup && !found)
	{
		async_write_str(CMD_ERROR, "backup not found");
		ret=-1;
	}
	if(regex) { regfree(regex); free(regex); }
	return ret;
}
