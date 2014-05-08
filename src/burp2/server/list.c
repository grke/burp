#include "include.h"
#include "monitor/status_client.h"

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
				goto error;
			if((cp=strchr(copy+1, '/'))) *cp='\0';
		}
		else
		{
			if(!(copy=strdup((*path)+bdlen+1)))
				goto error;
			if((cp=strchr(copy, '/'))) *cp='\0';
		}
	}
	else
	{
		if(!(copy=strdup((*path)+bdlen)))
			goto error;
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
		goto error;
	return 1;
error:
	if(copy) free(copy);
	log_out_of_memory(__func__);
	return -1;
}

static int list_manifest(struct async *as,
	const char *fullpath, regex_t *regex,
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
		log_and_send_oom(as, __func__);
		goto error;
	}
	manio_set_protocol(manio, conf->protocol);

	if(browsedir) bdlen=strlen(browsedir);

	while(1)
	{
		int show=0;

		if((ars=manio_sbuf_fill(manio, as, sb, NULL, NULL, conf))<0)
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
			if(as->write(as, &sb->attr)
			  || as->write(as, &sb->path))
				goto error;
			if(sbuf_is_link(sb)
			  && as->write(as, &sb->link))
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

static int send_backup_name_to_client(struct async *as, struct bu *arr)
{
	char msg[64]="";
	//snprintf(msg, sizeof(msg), "%s%s",
	//	arr->timestamp, arr->deletable?" (deletable)":"");
	snprintf(msg, sizeof(msg), "%s", arr->timestamp);
	return as->write_str(as, CMD_TIMESTAMP, msg);
}

int do_list_server(struct async *as, struct sdirs *sdirs, struct conf *conf,
	const char *backup, const char *listregex, const char *browsedir)
{
	int a=0;
	int i=0;
	int ret=-1;
	uint8_t found=0;
	struct bu *arr=NULL;
	unsigned long index=0;
	regex_t *regex=NULL;

	printf("in do_list_server\n");

	if(compile_regex(&regex, listregex)
	  || get_current_backups(as, sdirs, &arr, &a, 1)
	  || write_status(STATUS_LISTING, NULL, conf))
		goto end;

	if(backup && *backup) index=strtoul(backup, NULL, 10);

	for(i=0; i<a; i++)
	{
		// Search all backups for things matching the regex.
		if(listregex && backup && *backup=='a')
		{
			found=1;
			if(as->write_str(as, CMD_TIMESTAMP, arr[i].timestamp)
			  || list_manifest(as, arr[i].path,
				regex, browsedir, conf)) goto end;
		}
		// Search or list a particular backup.
		else if(backup && *backup)
		{
			if(!found
			  && (!strcmp(arr[i].timestamp, backup)
				|| arr[i].index==index))
			{
				found=1;
				if(send_backup_name_to_client(as, &(arr[i]))
				  || list_manifest(as, arr[i].path, regex,
					browsedir, conf)) goto end;
			}
		}
		// List the backups.
		else
		{
			found=1;
			if(send_backup_name_to_client(as, &(arr[i])))
				goto end;
		}
	}

	if(backup && *backup && !found)
	{
		as->write_str(as, CMD_ERROR, "backup not found");
		goto end;
	}
	ret=0;
end:
	if(regex) { regfree(regex); free(regex); }
	free_current_backups(&arr, a);
	return ret;
}
