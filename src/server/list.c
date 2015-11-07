#include "../burp.h"
#include "../alloc.h"
#include "../asfd.h"
#include "../async.h"
#include "../attribs.h"
#include "../bu.h"
#include "../cmd.h"
#include "../cntr.h"
#include "../log.h"
#include "../prepend.h"
#include "../regexp.h"
#include "bu_get.h"
#include "child.h"
#include "list.h"
#include "manio.h"

enum list_mode
{
	LIST_MODE_BACKUPS=0,
	LIST_MODE_CONTENTS_ONE,
	LIST_MODE_CONTENTS_MANY,
};

static struct asfd *asfd;
static struct cntr *cntr;
static enum protocol protocol;
static const char *backup;
static regex_t *regex=NULL;
static const char *browsedir;
static struct bu *bu_list=NULL;
static enum list_mode list_mode;
static unsigned long bno=0;

int list_server_init(
	struct asfd *a,
	struct sdirs *s,
	struct cntr *c,
	enum protocol p,
	const char *backup_str,
	const char *regex_str,
	const char *browsedir_str)
{
	asfd=a;
	cntr=c;
	protocol=p;
	backup=backup_str;
	browsedir=browsedir_str;
	if(bu_get_list(s, &bu_list))
		goto error;
	if(regex_str
	  && *regex_str
	  && !(regex=regex_compile(regex_str)))
		goto error;
	list_mode=LIST_MODE_BACKUPS;
	if(regex)
		list_mode=LIST_MODE_CONTENTS_MANY;
	if(backup)
	{
		if((bno=strtoul(backup, NULL, 10))>0)
			list_mode=LIST_MODE_CONTENTS_ONE;
		else if(*backup=='c')
			list_mode=LIST_MODE_CONTENTS_ONE;
		else if(*backup=='a')
			list_mode=LIST_MODE_CONTENTS_MANY;
		else
			list_mode=LIST_MODE_CONTENTS_ONE;
	}
	return 0;
error:
	list_server_free();
	return -1;
}

void list_server_free(void)
{
	bu_list_free(&bu_list);
	regex_free(&regex);
}

int check_browsedir(const char *browsedir,
	struct sbuf *mb, size_t bdlen, char **last_bd_match)
{
	char *cp=mb->path.buf;
	char *copy=NULL;
	if(bdlen>0)
	{
		if(strncmp(browsedir, cp, bdlen))
			return 0;
		cp+=bdlen;
		if(browsedir[bdlen-1]!='/')
		{
			if(*cp!='\0')
			{
				if(*cp!='/') return 0;
				cp++;
			}
		}
	}
	if(*cp=='\0') cp=(char *)".";
	if(!(copy=strdup_w(cp, __func__))) goto error;
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
			attribs_encode(mb);
		}
	}

	// Strip off possible trailing slash.
	if((cp=strrchr(copy, '/')) && cp>copy) *cp='\0';

	if(*last_bd_match)
	{
		if(!strcmp(*last_bd_match, copy))
		{
			// Got a duplicate match.
			free_w(&copy);
			return 0;
		}
		free(*last_bd_match);
	}
	free_w(&mb->path.buf);
	mb->path.buf=copy;
	if(!(*last_bd_match=strdup_w(copy, __func__)))
		goto error;
	return 1;
error:
	free_w(&copy);
	log_out_of_memory(__func__);
	return -1;
}

static int list_manifest(const char *fullpath)
{
	int ret=0;
	struct sbuf *sb=NULL;
	struct manio *manio=NULL;
	char *manifest_dir=NULL;
	char *last_bd_match=NULL;
	size_t bdlen=0;

	if(!(manifest_dir=prepend_s(fullpath,
		protocol==PROTO_1?"manifest.gz":"manifest"))
	  || !(manio=manio_open(manifest_dir, "rb", protocol))
	  || !(sb=sbuf_alloc(protocol)))
	{
		log_and_send_oom(asfd, __func__);
		goto error;
	}

	if(browsedir) bdlen=strlen(browsedir);

	while(1)
	{
		int show=0;
		sbuf_free_content(sb);

		switch(manio_read(manio, sb))
		{
			case 0: break;
			case 1: if(browsedir && *browsedir && !last_bd_match)
					asfd_write_wrapper_str(asfd,
						CMD_ERROR,
						"directory not found");
				goto end; // Finished OK.
			default: goto error;
		}

		if(protocol==PROTO_2 && sb->endfile.buf)
			continue;
		if(sbuf_is_metadata(sb))
			continue;

		if(write_status(CNTR_STATUS_LISTING, sb->path.buf, cntr))
			goto error;

		if(browsedir)
		{
			int r;
			if((r=check_browsedir(browsedir,
				sb, bdlen, &last_bd_match))<0)
					goto error;
			if(!r) continue;
			show++;
		}
		else
		{
			if(regex_check(regex, sb->path.buf))
				show++;
		}
		if(show)
		{
			if(asfd_write_wrapper(asfd, &sb->attr)
			  || asfd_write_wrapper(asfd, &sb->path))
				goto error;
			if(sbuf_is_link(sb)
			  && asfd_write_wrapper(asfd, &sb->link))
				goto error;
		}
	}

error:
	ret=-1;
end:
	sbuf_free(&sb);
	free_w(&manifest_dir);
	manio_close(&manio);
	free_w(&last_bd_match);
	return ret;
}

static int send_backup_name_to_client(struct bu *bu)
{
	char msg[64]="";
	snprintf(msg, sizeof(msg), "%s%s",
		bu->timestamp,
		// Protocol2 backups are all deletable, so do not mention it.
		protocol==PROTO_1
		&& (bu->flags & BU_DELETABLE)?" (deletable)":"");
	return asfd_write_wrapper_str(asfd, CMD_TIMESTAMP, msg);
}

static int list_all_backups(void)
{
	int found=0;
	struct bu *bu=NULL;
	for(bu=bu_list; bu; bu=bu->next)
	{
		found=1;
		if(send_backup_name_to_client(bu))
			return -1;
	}
	return found;
}

static int list_contents_one(
	int list_server_callback(const char *fullpath))
{
	struct bu *bu=NULL;
	for(bu=bu_list; bu; bu=bu->next)
	{
		if(!strcmp(bu->timestamp, backup)
		  || bu->bno==bno
		  || (*backup=='c' && (bu->flags & BU_CURRENT)))
		{
			if(send_backup_name_to_client(bu)
			  || list_server_callback(bu->path))
				return -1;
			return 1;
		}
	}
	return 0;
}

static int list_contents_many(
	int list_server_callback(const char *fullpath))
{
	int found=0;
	struct bu *bu=NULL;
	for(bu=bu_list; bu; bu=bu->next)
	{
		found=1;
		if(send_backup_name_to_client(bu)
		  || list_server_callback(bu->path))
			return -1;
	}
	return found;
}

#ifndef UTEST
static
#endif
int do_list_server_work(
	int list_server_callback(const char *fullpath))
{
	int ret=-1;
	int found=0;

	//logp("in do_list_server\n");

	if(write_status(CNTR_STATUS_LISTING, NULL, cntr))
		goto end;

	switch(list_mode)
	{
		case LIST_MODE_BACKUPS:
			if((found=list_all_backups())<0)
				goto end;
			break;
		case LIST_MODE_CONTENTS_ONE:
			if((found=list_contents_one(list_server_callback))<0)
				goto end;
			break;
		case LIST_MODE_CONTENTS_MANY:
			if((found=list_contents_many(list_server_callback))<0)
				goto end;
			break;
	}

	if(!found)
	{
		asfd_write_wrapper_str(asfd, CMD_ERROR, "backup not found");
		asfd_flush_asio(asfd);
		goto end;
	}

	if(asfd_flush_asio(asfd)) goto end;

	ret=0;
end:
	return ret;
}

int do_list_server(void)
{
	return do_list_server_work(list_manifest);
}
