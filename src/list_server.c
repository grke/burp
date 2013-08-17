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
	gzFile zp=NULL;
	char *manifest=NULL;
	size_t bdlen=0;
	struct sbuf *sb=NULL;

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
	if(!(sb=sbuf_alloc())) return -1;

	if(browsedir) bdlen=strlen(browsedir);

	while(1)
	{
		int show=0;

		if(sbuf_fill_from_gzfile(sb, zp, NULL, conf)) goto error;

		write_status(client, STATUS_LISTING, sb->path, conf);

		if(browsedir)
		{
			int r;
			if((r=check_browsedir(browsedir, &sb->path, bdlen))<0)
			{
				goto error;
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
				goto error;
			if(sbuf_is_link(sb)
			  && async_write(sb->cmd, sb->linkto, sb->llen))
				goto error;
		}

		sbuf_free_contents(sb);
	}

	goto end;
error:
	ret=-1;
end:
	gzclose_fp(&zp);
	sbuf_free(sb);
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
