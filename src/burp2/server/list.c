#include "include.h"

int check_browsedir(const char *browsedir, char **path,
	size_t bdlen, char **last_bd_match)
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
	const char *browsedir, struct conf *conf)
{
	int ars=0;
	int ret=0;
	struct sbuf *sb=NULL;
	struct manio *manio=NULL;
	char *manifest_dir=NULL;
	char *last_bd_match=NULL;
	size_t bdlen=0;

	if(!(manifest_dir=prepend_s(fullpath,
		conf->protocol==PROTO_BURP1?"manifest.gz":"manifest"))
	  || !(manio=manio_alloc())
	  || manio_init_read(manio, manifest_dir)
	  || !(sb=sbuf_alloc(conf)))
	{
		log_and_send_oom(__FUNCTION__);
		goto error;
	}
	manio_set_protocol(manio, conf->protocol);

	if(browsedir) bdlen=strlen(browsedir);

	while(1)
	{
		int show=0;

		if((ars=manio_sbuf_fill(manio, sb, NULL, NULL, conf))<0)
			goto error;
		else if(ars>0)
			goto end; // Finished OK.

		if(write_status(STATUS_LISTING, sb->path.buf, conf))
			goto error;

		if(browsedir)
		{
			int r;
			if((r=check_browsedir(browsedir,
				&sb->path.buf, bdlen, &last_bd_match))<0)
					goto error;
			if(!r) continue;
			show++;
		}
		else
		{
			if(check_regex(regex, sb->path.buf))
				show++;
		}
		if(show)
		{
			if(async_write(&sb->attr)
			  || async_write(&sb->path))
				goto error;
			if(sbuf_is_link(sb)
			  && async_write(&sb->link))
				goto error;
		}

		sbuf_free_content(sb);
	}

error:
	ret=-1;
end:
	sbuf_free(sb);
	if(manifest_dir) free(manifest_dir);
	manio_free(manio);
	if(last_bd_match) free(last_bd_match);
	return ret;
}

static void send_backup_name_to_client(struct bu *arr)
{
	char msg[64]="";
	//snprintf(msg, sizeof(msg), "%s%s",
	//	arr->timestamp, arr->deletable?" (deletable)":"");
	snprintf(msg, sizeof(msg), "%s", arr->timestamp);
	async_write_str(CMD_TIMESTAMP, msg);
}

int do_list_server(struct sdirs *sdirs, struct conf *conf,
	const char *backup, const char *listregex, const char *browsedir)
{
	int a=0;
	int i=0;
	int ret=0;
	uint8_t found=0;
	struct bu *arr=NULL;
	unsigned long index=0;
	regex_t *regex=NULL;

	printf("in do_list_server\n");

	if(compile_regex(&regex, listregex)) return -1;

	if(get_current_backups(sdirs, &arr, &a, 1)
	  || write_status(STATUS_LISTING, NULL, conf))
	{
		if(regex) { regfree(regex); free(regex); }
		return -1;
	}

	if(backup && *backup) index=strtoul(backup, NULL, 10);

	for(i=0; i<a; i++)
	{
		// Search all backups for things matching the regex.
		if(listregex && backup && *backup=='a')
		{
			found=1;
			async_write_str(CMD_TIMESTAMP, arr[i].timestamp);
			ret+=list_manifest(arr[i].path, regex, browsedir, conf);
		}
		// Search or list a particular backup.
		else if(backup && *backup)
		{
			if(!found
			  && (!strcmp(arr[i].timestamp, backup)
				|| arr[i].index==index))
			{
				found=1;
				send_backup_name_to_client(&(arr[i]));
				ret=list_manifest(arr[i].path, regex,
					browsedir, conf);
			}
		}
		// List the backups.
		else
		{
			found=1;
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
