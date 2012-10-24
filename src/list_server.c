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
#include "regexp.h"
#include "list_server.h"
#include "current_backups_server.h"

int check_browsedir(const char *browsedir, char **path, size_t bdlen, char **lastpath)
{
	char *cp=NULL;
	char *copy=NULL;
//	if(strncmp(browsedir, *path, bdlen)
//	  || (bdlen && (*path)[bdlen]!='\0' && (*path)[bdlen]!='/'))
	if(strncmp(browsedir, *path, bdlen))
		return 0;
	if((*path)[bdlen+1]=='\0') return 0;

	/* Lots of messing around related to whether browsedir was '', '/', or
   	   something else. */
	if(*browsedir)
	{
		if(!strcmp(browsedir, "/"))
		{
			if(!(copy=strdup((*path)+bdlen)))
				goto err;
			if((cp=strchr(copy+1, '/'))) *cp='\0';
		}
		else
		{
			if(!(copy=strdup((*path)+bdlen+1)))
				goto err;
			if((cp=strchr(copy, '/'))) *cp='\0';
		}
	}
	else
	{
		if(!(copy=strdup((*path)+bdlen)))
		{
			log_out_of_memory(__FUNCTION__);
			return -1;
		}
		if(*copy=='/') *(copy+1)='\0';
		// Messing around for Windows.
		else if(strlen(copy)>2 && copy[1]==':' && copy[2]=='/')
			copy[2]='\0';
	}
	if(*lastpath && !strcmp(*lastpath, copy))
	{
		free(copy);
		return 0;
	}
	free(*path);
	*path=copy;
	if(*lastpath) free(*lastpath);
	if(!(*lastpath=strdup(copy)))
		goto err;
	return 1;
err:
	if(copy) free(copy);
	if(*lastpath) free(*lastpath);
	log_out_of_memory(__FUNCTION__);
	return -1;
}

static int list_manifest(const char *fullpath, regex_t *regex, const char *browsedir, const char *client, struct cntr *p1cntr, struct cntr *cntr)
{
	int ars=0;
	int ret=0;
	int quit=0;
	gzFile zp=NULL;
	struct sbuf mb;
	char *manifest=NULL;
	size_t bdlen=0;
	char *lastpath=NULL;

	init_sbuf(&mb);

	if(!(manifest=prepend_s(fullpath,
		"manifest.gz", strlen("manifest.gz"))))
	{
		log_and_send_oom(__FUNCTION__);
		return -1;
	}
	if(!(zp=gzopen_file(manifest, "rb")))
	{
		log_and_send("could not open manifest");
		free(manifest);
		return -1;
	}
	free(manifest);

	if(browsedir) bdlen=strlen(browsedir);

	while(!quit)
	{
		int show=0;
		//logp("list manifest loop\n");
		// Need to parse while sending, to take note of the regex.

		free_sbuf(&mb);
		if((ars=sbuf_fill(NULL, zp, &mb, cntr)))
		{
			if(ars<0) ret=-1;
			// ars==1 means it ended ok.
			break;
		}

		//if(mb.path[mb.plen]=='\n') mb.path[mb.plen]='\0';
		write_status(client, STATUS_LISTING, mb.path, p1cntr, cntr);

		if(browsedir)
		{
			int r;
			if((r=check_browsedir(browsedir,
				&(mb.path), bdlen, &lastpath))<0)
			{
				quit++;
				ret=-1;
			}
			if(!r) continue;
			show++;
		}
		else
		{
			if(check_regex(regex, mb.path))
				show++;
		}
		if(show)
		{
			if(async_write(CMD_STAT, mb.statbuf, mb.slen)
			  || async_write(mb.cmd, mb.path, mb.plen))
			{ quit++; ret=-1; }
			else if(sbuf_is_link(&mb)
			  && async_write(mb.cmd, mb.linkto, mb.llen))
			{ quit++; ret=-1; }
		}
	}
	gzclose_fp(&zp);
	free_sbuf(&mb);
	if(lastpath) free(lastpath);
	return ret;
}

int do_list_server(const char *basedir, const char *backup, const char *listregex, const char *browsedir, const char *client, struct cntr *p1cntr, struct cntr *cntr)
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
			ret+=list_manifest(arr[i].path, regex, browsedir,
				client, p1cntr, cntr);
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
				ret=list_manifest(arr[i].path, regex,
					browsedir, client, p1cntr, cntr);
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
