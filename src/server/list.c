#include "../burp.h"
#include "../alloc.h"
#include "../asfd.h"
#include "../async.h"
#include "../attribs.h"
#include "../bu.h"
#include "../cmd.h"
#include "../cntr.h"
#include "../cstat.h"
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
static struct conf **confs;
static struct cntr *cntr;
static const char *backup;
static regex_t *regex=NULL;
static const char *browsedir;
static struct bu *bu_list=NULL;
static enum list_mode list_mode;
static unsigned long bno=0;

int list_server_init(
	struct asfd *a,
	struct sdirs *s,
	struct conf **c,
	const char *backup_str,
	const char *regex_str,
	const char *browsedir_str)
{
	int regex_case_insensitive=0;
	asfd=a;
	confs=c;
	backup=backup_str;
	browsedir=browsedir_str;
	if(confs)
	{
		cntr=get_cntr(confs);
		regex_case_insensitive=get_int(
			confs[OPT_REGEX_CASE_INSENSITIVE]
		);
	}

	if(bu_get_list_with_working(s, &bu_list))
		goto error;
	if(regex_str
	  && *regex_str
	  && !(regex=regex_compile_restore( regex_str, regex_case_insensitive)))
	{
		char msg[256]="";
		snprintf(msg, sizeof(msg), "unable to compile regex: %s\n",
			regex_str);
		log_and_send(asfd, msg);
		goto error;
	}
	list_mode=LIST_MODE_BACKUPS;
	if(regex || browsedir)
		list_mode=LIST_MODE_CONTENTS_MANY;
	if(backup && *backup)
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

#ifndef UTEST
static
#endif
void maybe_fake_directory(struct sbuf *mb)
{
	if(S_ISDIR(mb->statp.st_mode))
		return;
	// We are faking a directory entry.
	// Make sure the directory bit is set.
	mb->statp.st_mode &= ~(S_IFMT);
	mb->statp.st_mode |= S_IFDIR;

	// Need to free attr so that it is reallocated, because it may get
	// longer than what we initially had.
	iobuf_free_content(&mb->attr);
	attribs_encode(mb);
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
				if(*cp!='/')
					return 0;
				cp++;
			}
		}
	}
	if(*cp=='\0')
		cp=(char *)".";
	if(!(copy=strdup_w(cp, __func__)))
		goto error;
	if((cp=strchr(copy, '/')))
	{
		if(bdlen==0) cp++;
		*cp='\0';

		maybe_fake_directory(mb);
	}
	else if(!strcmp(mb->path.buf, "/")
	  && !strcmp(browsedir, "/"))
		maybe_fake_directory(mb);
	else if(mb->path.cmd==CMD_DIRECTORY)
		maybe_fake_directory(mb);

	// Strip off possible trailing slash.
	if((cp=strrchr(copy, '/')) && cp>copy)
		*cp='\0';

	if(*last_bd_match
	  && !strcmp(*last_bd_match, copy))
	{
		// Got a duplicate match.
		free_w(&copy);
		return 0;
	}
	free_w(&mb->path.buf);
	mb->path.buf=copy;
	free_w(last_bd_match);
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

	if(!(manifest_dir=prepend_s(fullpath, "manifest.gz"))
	  || !(manio=manio_open(manifest_dir, "rb"))
	  || !(sb=sbuf_alloc()))
	{
		log_and_send_oom(asfd);
		goto error;
	}

	if(browsedir) bdlen=strlen(browsedir);

	while(1)
	{
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

		if(sbuf_is_metadata(sb))
			continue;

		if(timed_operation_status_only(CNTR_STATUS_LISTING,
			sb->path.buf, confs)) goto error;

		if(browsedir)
		{
			int r;
			if((r=check_browsedir(browsedir,
				sb, bdlen, &last_bd_match))<0)
					goto error;
			if(!r) continue;
		}

		if(regex && !regex_check(regex, sb->path.buf))
			continue;

		if(asfd_write_wrapper(asfd, &sb->attr)
		  || asfd_write_wrapper(asfd, &sb->path))
			goto error;
		if(sbuf_is_link(sb)
		  && asfd_write_wrapper(asfd, &sb->link))
			goto error;
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

static char *get_extradesc(struct bu *bu)
{
	if(bu->flags & BU_WORKING)
		return strdup_w(" (working)", __func__);
	else if(bu->flags & BU_FINISHING)
		return strdup_w(" (finishing)", __func__);
	// Protocol2 backups are all deletable, so do not mention it.
	else if(bu->flags & BU_DELETABLE)
		return strdup_w(" (deletable)", __func__);
	return strdup_w("", __func__);
}

static int send_backup_name_to_client(struct bu *bu)
{
	int ret;
	char msg[64]="";
	char *extradesc;
	if(!(extradesc=get_extradesc(bu)))
		return -1;
	snprintf(msg, sizeof(msg), "%s%s", bu->timestamp, extradesc);
	ret=asfd_write_wrapper_str(asfd, CMD_TIMESTAMP, msg);
	free_w(&extradesc);
	return ret;
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
			if(cntr)
				cntr->bno=bu->bno;
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
		if(cntr)
			cntr->bno=bu->bno;
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

	if(timed_operation_status_only(CNTR_STATUS_LISTING, NULL, confs))
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
		if(list_mode==LIST_MODE_BACKUPS)
		{
			asfd_write_wrapper_str(asfd,
				CMD_MESSAGE, "no backups");
			// Success.
		}
		else
		{
			asfd_write_wrapper_str(asfd,
				CMD_MESSAGE, "backup not found");
			goto end;
		}
	}

	ret=0;
end:
	bu_list_free(&bu_list);
	return ret;
}

int do_list_server(void)
{
	return do_list_server_work(list_manifest);
}
