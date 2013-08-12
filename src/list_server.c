#include "burp.h"
#include "prog.h"
#include "msg.h"
#include "lock.h"
#include "handy.h"
#include "asyncio.h"
#include "zlibio.h"
#include "counter.h"
#include "dpth.h"
#include "sbuf.h"
#include "regexp.h"
#include "list_server.h"
#include "current_backups_server.h"

int check_browsedir(const char *browsedir, char **path, size_t bdlen)
{
	char *cp=NULL;
	char *copy=NULL;
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
			goto err;
		if(*copy=='/') *(copy+1)='\0';
		// Messing around for Windows.
		else if(strlen(copy)>2 && copy[1]==':' && copy[2]=='/')
			copy[2]='\0';
	}
	free(*path);
	*path=copy;
	return 1;
err:
	if(copy) free(copy);
	log_out_of_memory(__FUNCTION__);
	return -1;
}

static int list_manifest(const char *fullpath, regex_t *regex, const char *browsedir, const char *client, struct config *conf)
{
	int ret=-1;
	int quit=0;
	gzFile zp=NULL;
	char *manifest=NULL;
	size_t bdlen=0;
	struct sbuf *sb=NULL;
	struct iobuf *rbuf=NULL;
	char lead[5]="";
	int sb_ok=0;
	unsigned int s;

	if(!(sb=sbuf_init())
	  || !(rbuf=iobuf_init()))
		return -1;

	if(!(manifest=prepend_s(fullpath,
		"manifest.gz", strlen("manifest.gz"))))
	{
		log_and_send_oom(__FUNCTION__);
		goto error;
	}
	if(!(zp=gzopen_file(manifest, "rb")))
	{
		log_and_send("could not open manifest");
		goto error;
	}

	if(browsedir) bdlen=strlen(browsedir);

	while(!quit)
	{
		int show=0;
		size_t got;

		if((got=gzread(zp, lead, sizeof(lead)))!=5)
		{
			if(!got) break; // Finished OK.
			log_and_send("short read in manifest");
			goto error;
		}
		if((sscanf(lead, "%c%04X", &rbuf->cmd, &s))!=2)
		{
			log_and_send("sscanf failed reading manifest");
			goto error;
		}
		rbuf->len=(size_t)s;
		if(!(rbuf->buf=(char *)malloc(rbuf->len+2)))
		{
			log_and_send_oom(__FUNCTION__);
			goto error;
		}
		if(gzread(zp, rbuf->buf, rbuf->len+1)!=(int)rbuf->len+1)
		{
			log_and_send("short read in manifest");
			goto error;
		}
		rbuf->buf[rbuf->len]='\0';

		switch(rbuf->cmd)
		{
			case CMD_ATTRIBS:
				sbuf_from_iobuf_attr(sb, rbuf);
				rbuf->buf=NULL;
				break;

			case CMD_FILE:
			case CMD_DIRECTORY:
			case CMD_SOFT_LINK:
			case CMD_HARD_LINK:
			case CMD_SPECIAL:
				if(!sb->attribs)
				{
					log_and_send("read cmd with no attribs");
					goto error;
				}
				if(sb->need_link)
				{
					if(cmd_is_link(rbuf->cmd))
					{
						sbuf_from_iobuf_link(sb, rbuf);
						sb->need_link=0;
						sb_ok=1;
					}
					else
					{
						log_and_send("got non-link after link in manifest");
						goto error;
					}
				}
				else
				{
					sbuf_from_iobuf_path(sb, rbuf);
					if(cmd_is_link(rbuf->cmd))
						sb->need_link=1;
					else
						sb_ok=1;
				}
				rbuf->buf=NULL;
				break;

			default:
				break;
		}
		if(rbuf->buf) { free(rbuf->buf); rbuf->buf=NULL; }

		if(!sb_ok) continue;

		write_status(client, STATUS_LISTING, sb->path, conf);

		if(browsedir)
		{
			int r;
			if((r=check_browsedir(browsedir, &sb->path, bdlen))<0)
			{
				quit++;
				ret=-1;
			}
			if(!r) continue;
			show++;
		}
		else
		{
			if(check_regex(regex, sb->path))
				show++;
		}
		if(show)
		{
			if(async_write(CMD_ATTRIBS, sb->attribs, sb->alen)
			  || async_write(sb->cmd, sb->path, sb->plen))
			{ quit++; ret=-1; }
			else if(sbuf_is_link(sb)
			  && async_write(sb->cmd, sb->linkto, sb->llen))
			{ quit++; ret=-1; }
		}

		if(sb->path) { free(sb->path); sb->path=NULL; }
		if(sb->attribs) { free(sb->attribs); sb->attribs=NULL; }
		if(sb->linkto) { free(sb->linkto); sb->linkto=NULL; }
		sb_ok=0;
	}

	goto end;
error:
	ret=-1;
end:
	gzclose_fp(&zp);
	sbuf_free(sb);
	if(rbuf->buf) { free(rbuf->buf); rbuf->buf=NULL; }
	iobuf_free(rbuf);
	if(manifest) free(manifest);
	return ret;
}

static void send_backup_name_to_client(struct bu *arr)
{
	char msg[64]="";
	snprintf(msg, sizeof(msg), "%s%s",
		arr->timestamp, arr->deletable?" (deletable)":"");
	async_write(CMD_TIMESTAMP, msg, strlen(msg));
}

int do_list_server(const char *basedir, const char *backup, const char *listregex, const char *browsedir, const char *client, struct config *conf)
{
	int a=0;
	int i=0;
	int ret=0;
	int found=0;
	struct bu *arr=NULL;
	unsigned long index=0;
	regex_t *regex=NULL;

	//printf("in do_list\n");

	if(compile_regex(&regex, listregex)) return -1;

	if(get_current_backups(basedir, &arr, &a, 1))
	{
		if(regex) { regfree(regex); free(regex); }
		return -1;
	}

	write_status(client, STATUS_LISTING, NULL, conf);

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
				client, conf);
		}
		// Search or list a particular backup.
		else if(backup && *backup)
		{
			if(!found
			  && (!strcmp(arr[i].timestamp, backup)
				|| arr[i].index==index))
			{
				found=TRUE;
				send_backup_name_to_client(&(arr[i]));
				ret=list_manifest(arr[i].path, regex,
					browsedir, client, conf);
			}
		}
		// List the backups.
		else
		{
			found=TRUE;
			send_backup_name_to_client(&(arr[i]));
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
