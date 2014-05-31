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

static int list_manifest(struct asfd *asfd,
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
		log_and_send_oom(asfd, __func__);
		goto error;
	}
	manio_set_protocol(manio, conf->protocol);

	if(browsedir) bdlen=strlen(browsedir);

	while(1)
	{
		int show=0;

		if((ars=manio_sbuf_fill(manio, asfd, sb, NULL, NULL, conf))<0)
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
			if(asfd->write(asfd, &sb->attr)
			  || asfd->write(asfd, &sb->path))
				goto error;
			if(sbuf_is_link(sb)
			  && asfd->write(asfd, &sb->link))
				goto error;
		}

		sbuf_free_content(sb);
	}

error:
	ret=-1;
end:
	sbuf_free(&sb);
	free_w(&manifest_dir);
	manio_free(&manio);
	free_w(&last_bd_match);
	return ret;
}

static int send_backup_name_to_client(struct asfd *asfd, struct bu *arr)
{
	char msg[64]="";
	//snprintf(msg, sizeof(msg), "%s%s",
	//	arr->timestamp, arr->deletable?" (deletable)":"");
	snprintf(msg, sizeof(msg), "%s", arr->timestamp);
	return asfd->write_str(asfd, CMD_TIMESTAMP, msg);
}

int do_list_server(struct asfd *asfd, struct sdirs *sdirs, struct conf *conf,
	const char *backup, const char *listregex, const char *browsedir)
{
	int a=0;
	int i=0;
	int ret=-1;
	uint8_t found=0;
	struct bu *arr=NULL;
	unsigned long bno=0;
	regex_t *regex=NULL;

	printf("in do_list_server\n");

	if(compile_regex(&regex, listregex)
	  || bu_get(asfd, sdirs, &arr, &a, 1)
	  || write_status(STATUS_LISTING, NULL, conf))
		goto end;

	if(backup && *backup) bno=strtoul(backup, NULL, 10);

	for(i=0; i<a; i++)
	{
		// Search all backups for things matching the regex.
		if(listregex && backup && *backup=='a')
		{
			found=1;
			if(asfd->write_str(asfd,
				CMD_TIMESTAMP, arr[i].timestamp)
			  || list_manifest(asfd, arr[i].path,
				regex, browsedir, conf)) goto end;
		}
		// Search or list a particular backup.
		else if(backup && *backup)
		{
			if(!found
			  && (!strcmp(arr[i].timestamp, backup)
				|| arr[i].bno==bno))
			{
				found=1;
				if(send_backup_name_to_client(asfd, &(arr[i]))
				  || list_manifest(asfd, arr[i].path, regex,
					browsedir, conf)) goto end;
			}
		}
		// List the backups.
		else
		{
			found=1;
			if(send_backup_name_to_client(asfd, &(arr[i])))
				goto end;
		}
	}

	if(backup && *backup && !found)
	{
		asfd->write_str(asfd, CMD_ERROR, "backup not found");
		goto end;
	}
	ret=0;
end:
	if(regex) { regfree(regex); free(regex); }
	bu_free(&arr, a);
	return ret;
}
