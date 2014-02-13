#include "include.h"

int check_browsedir(const char *browsedir, char **path, size_t bdlen, char **last_bd_match)
{
	char *cp=NULL;
	char *copy=NULL;
	if(strncmp(browsedir, *path, bdlen))
		return 0;
	if((*path)[bdlen+1]=='\0' || (bdlen>1 && (*path)[bdlen]!='/'))
		return 0;

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
	free(*path);
	*path=copy;
	if(!(*last_bd_match=strdup(copy)))
		goto err;
	return 1;
err:
	if(copy) free(copy);
	log_out_of_memory(__FUNCTION__);
	return -1;
}

static int list_manifest(const char *fullpath, regex_t *regex,
	const char *browsedir, struct config *conf)
{
	int ars=0;
	int ret=0;
	int quit=0;
	gzFile zp=NULL;
	struct sbufl mb;
	char *manifest=NULL;
	char *last_bd_match=NULL;
	size_t bdlen=0;

	init_sbufl(&mb);

	if(!(manifest=prepend_s(fullpath, "manifest.gz")))
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

		free_sbufl(&mb);
		if((ars=sbufl_fill(NULL, zp, &mb, conf->cntr)))
		{
			if(ars<0) ret=-1;
			// ars==1 means it ended ok.
			break;
		}

		if(mb.path.cmd!=CMD_DIRECTORY
		 && mb.path.cmd!=CMD_FILE
		 && mb.path.cmd!=CMD_ENC_FILE
		 && mb.path.cmd!=CMD_EFS_FILE
		 && mb.path.cmd!=CMD_SPECIAL
		 && !cmd_is_link(mb.path.cmd))
			continue;

		write_status(STATUS_LISTING, mb.path.buf, conf);

		if(browsedir)
		{
			int r;
			if((r=check_browsedir(browsedir,
				&(mb.path.buf), bdlen, &last_bd_match))<0)
			{
				quit++;
				ret=-1;
			}
			if(!r) continue;
			show++;
		}
		else
		{
			if(check_regex(regex, mb.path.buf))
				show++;
		}
		if(show)
		{
			if(async_write(&mb.attr)
			  || async_write(&mb.path))
			{
				quit++;
				ret=-1;
			}
			else if(sbufl_is_link(&mb)
			  && async_write(&mb.link))
			{
				quit++;
				ret=-1;
			}
		}
	}
	gzclose_fp(&zp);
	free_sbufl(&mb);
	if(last_bd_match) free(last_bd_match);
	return ret;
}

static void send_backup_name_to_client(struct bu *arr)
{
	char msg[64]="";
	snprintf(msg, sizeof(msg), "%s%s",
		arr->timestamp, arr->deletable?" (deletable)":"");
	async_write_str(CMD_TIMESTAMP, msg);
}

int do_list_server_legacy(struct sdirs *sdirs, struct config *conf,
	const char *backup, const char *listregex, const char *browsedir)
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

	if(get_current_backups(sdirs, &arr, &a, 1))
	{
		if(regex) { regfree(regex); free(regex); }
		return -1;
	}

	write_status(STATUS_LISTING, NULL, conf);

	if(backup && *backup) index=strtoul(backup, NULL, 10);

	for(i=0; i<a; i++)
	{
		// Search all backups for things matching the regex.
		if(listregex && backup && *backup=='a')
		{
			found=TRUE;
			async_write_str(CMD_TIMESTAMP, arr[i].timestamp);
			ret+=list_manifest(arr[i].path, regex, browsedir,
				conf);
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
					browsedir, conf);
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
