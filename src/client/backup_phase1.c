#include "include.h"

#include "../legacy/burpconfig.h"

static char filesymbol=CMD_FILE;
static char metasymbol=CMD_METADATA;
static char dirsymbol=CMD_DIRECTORY;

static long server_name_max;

static int usual_stuff(struct config *conf, const char *path, const char *link,
	const char *attribs, char cmd)
{
	if(async_write_str(CMD_ATTRIBS, attribs)
	  || async_write_str(cmd, path)
	  || ((cmd==CMD_HARD_LINK || cmd==CMD_SOFT_LINK)
		&& async_write_str(cmd, link)))
			return -1;
	do_filecounter(conf->p1cntr, cmd, 1);
	return 0;
}

static int maybe_send_extrameta(const char *path, char cmd,
	const char *attribs, struct config *conf)
{
	if(!has_extrameta(path, cmd)) return 0;
	return usual_stuff(conf, path, NULL, attribs, metasymbol);
}

static int ft_err(struct config *conf, FF_PKT *ff, const char *msg)
{
	return logw(conf->p1cntr, _("Err: %s %s: %s"), msg,
		ff->fname, strerror(errno));
}

static int do_to_server(struct config *conf, FF_PKT *ff,
	const char *attribs, char cmd, int compression) 
{
//	encode_stat(attribs, &ff->statp, ff->winattr, compression);
	if(usual_stuff(conf, ff->fname, ff->link, attribs, cmd)) return -1;

	if(ff->type==FT_REG)
		do_filecounter_bytes(conf->p1cntr,
			(unsigned long long)ff->statp.st_size);
	return maybe_send_extrameta(ff->fname, cmd, attribs, conf);
}

static int to_server(struct config *conf, FF_PKT *ff,
	const char *attribs, char cmd)
{
	return do_to_server(conf, ff, attribs, cmd, conf->compression);
}

int send_file(FF_PKT *ff, bool top_level, struct config *conf)
{
	char attribs[MAXSTRING];

	if(!file_is_included(conf, ff->fname, top_level)) return 0;

	if(server_name_max)
	{
		if(top_level)
		{
			char *cp=NULL;
			// Need to figure out the length of the filename
			// component.
			if((cp=strrchr(ff->fname, '/'))) ff->flen=strlen(cp+1);
			else ff->flen=strlen(ff->fname);	
		}
		if(ff->flen>server_name_max)
			return logw(conf->p1cntr,
				"File name too long (%lu > %lu): %s",
				ff->flen, server_name_max, ff->fname);
	}

#ifdef HAVE_WIN32
	if(ff->winattr & FILE_ATTRIBUTE_ENCRYPTED)
	{
		if(ff->type==FT_REG
		  || ff->type==FT_DIR)
			return to_server(conf, ff, attribs, CMD_EFS_FILE);
		return logw(conf->p1cntr, "EFS type %d not yet supported: %s",
			ff->type, ff->fname);
	}
#endif

	switch(ff->type)
	{
		case FT_REG:
		case FT_RAW:
		case FT_FIFO:
			return do_to_server(conf, ff, attribs, filesymbol,
				in_exclude_comp(conf->excom,
					ff->fname, conf->compression));
		case FT_DIR:
		case FT_REPARSE:
		case FT_JUNCTION:
			return to_server(conf, ff, attribs, dirsymbol);
		case FT_LNK_S:
			return to_server(conf, ff, attribs, CMD_SOFT_LINK);
		case FT_LNK_H:
			return to_server(conf, ff, attribs, CMD_HARD_LINK);
		case FT_SPEC:
			return to_server(conf, ff, attribs, CMD_SPECIAL);
		case FT_NOFSCHG:
			return logw(conf->p1cntr, "Dir: %s [will not descend: "
				"file system change not allowed]\n", ff->fname);
		case FT_NOFOLLOW:
			return ft_err(conf, ff, "Could not follow link");
		case FT_NOSTAT:
			return ft_err(conf, ff, "Could not stat");
		case FT_NOOPEN:
			return ft_err(conf, ff, "Could not open directory");
		default:
			return logw(conf->p1cntr,
				_("Err: Unknown file type %d: %s"),
				ff->type, ff->fname);
	}
}

int backup_phase1_client(struct config *conf, long name_max, int estimate)
{
	int ret=0;
	FF_PKT *ff=NULL;
	struct strlist *l;

	// First, tell the server about everything that needs to be backed up.

	logp("Phase 1 begin (file system scan)\n");

	if(conf->encryption_password)
	{
		filesymbol=CMD_ENC_FILE;
		metasymbol=CMD_ENC_METADATA;
#ifdef HAVE_WIN32
		dirsymbol=filesymbol;
#endif
	}

	ff=find_files_init();
	server_name_max=name_max;
	for(l=conf->startdir; l; l=l->next) if(l->flag)
		if((ret=find_files_begin(ff, conf, l->path)))
			break;
	find_files_free(ff);

	print_endcounter(conf->p1cntr);
	if(ret) logp("Error in phase 1\n");
	logp("Phase 1 end (file system scan)\n");

	return ret;
}
