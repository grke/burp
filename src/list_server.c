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

static int read_and_write(char wcmd, const char *wsrc, size_t *wlen)
{
	static char rcmd='\0';
	static char *rdst=NULL;
	static size_t rlen=0;
	if(async_rw(&rcmd, &rdst, &rlen, wcmd, wsrc, wlen)) return -1;
	if(!rdst) return 0;
	logp("unexpected message from client: %c:%s\n", rcmd, rdst);
	free(rdst); rdst=NULL;
	return -1;
}

static int flush_asio(void)
{
	while(writebuflen>0) if(read_and_write('\0', NULL, NULL)) return -1;
	return 0;
}

static int write_wrapper(char wcmd, const char *wsrc, size_t *wlen)
{
	while(*wlen>0) if(read_and_write(wcmd, wsrc, wlen)) return -1;
	return 0;
}

static int write_wrapper_str(char wcmd, const char *wsrc)
{
	size_t wlen=strlen(wsrc);
	return write_wrapper(wcmd, wsrc, &wlen);
}

int check_browsedir(const char *browsedir,
	struct sbuf *mb, size_t bdlen, char **last_bd_match)
{
	char *cp=mb->path;
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
	if(!(copy=strdup(cp))) goto err;
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
			encode_stat(mb->statbuf,
				&mb->statp, mb->winattr, mb->compression);
		}
	}

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
	free(mb->path);
	mb->path=copy;
	if(!(*last_bd_match=strdup(copy)))
		goto err;
	return 1;
err:
	if(copy) free(copy);
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
	char *last_bd_match=NULL;
	size_t bdlen=0;
	int isdir=0;

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

		if(mb.cmd!=CMD_DIRECTORY
		 && mb.cmd!=CMD_FILE
		 && mb.cmd!=CMD_ENC_FILE
		 && mb.cmd!=CMD_EFS_FILE
		 && mb.cmd!=CMD_SPECIAL
		 && !cmd_is_link(mb.cmd))
			continue;

		//if(mb.path[mb.plen]=='\n') mb.path[mb.plen]='\0';
		write_status(client, STATUS_LISTING, mb.path, p1cntr, cntr);

		if(browsedir)
		{
			int r;
			if((r=check_browsedir(browsedir,
				&mb, bdlen, &last_bd_match))<0)
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
			if(write_wrapper(CMD_STAT, mb.statbuf, &mb.slen)
			  || write_wrapper(mb.cmd, mb.path, &mb.plen))
			{ quit++; ret=-1; }
			else if(sbuf_is_link(&mb)
			  && write_wrapper(mb.cmd, mb.linkto, &mb.llen))
			{ quit++; ret=-1; }
		}
	}
	gzclose_fp(&zp);
	free_sbuf(&mb);
	if(last_bd_match) free(last_bd_match);
	return ret;
}

static int send_backup_name_to_client(struct bu *arr)
{
	char msg[64]="";
	snprintf(msg, sizeof(msg), "%s%s",
		arr->timestamp, arr->deletable?" (deletable)":"");
	return write_wrapper_str(CMD_TIMESTAMP, msg);
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
			if(write_wrapper_str(CMD_TIMESTAMP, arr[i].timestamp))
			{
				ret=-1;
				break;
			}
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
				if(send_backup_name_to_client(&(arr[i])))
				{
					ret=-1;
					break;
				}
				ret=list_manifest(arr[i].path, regex,
					browsedir, client, p1cntr, cntr);
			}
		}
		// List the backups.
		else
		{
			found=TRUE;
			if(send_backup_name_to_client(&(arr[i])))
			{
				ret=-1;
				break;
			}
		}
	}
	free_current_backups(&arr, a);

	if(backup && *backup && !found)
	{
		write_wrapper_str(CMD_ERROR, "backup not found");
		ret=-1;
	}
	if(!ret) ret=flush_asio();
	if(regex) { regfree(regex); free(regex); }
	return ret;
}
