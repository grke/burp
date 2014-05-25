#include "include.h"

static char filesymbol=CMD_FILE;
static char metasymbol=CMD_METADATA;
static char dirsymbol=CMD_DIRECTORY;
#ifdef HAVE_WIN32
static char vss_trail_symbol=CMD_VSS_T;
#endif

static long server_name_max;

static int usual_stuff(struct asfd *asfd,
	struct conf *conf, const char *path, const char *link,
	struct sbuf *sb, char cmd)
{
	if(asfd->write_str(asfd, CMD_ATTRIBS, sb->attr.buf)
	  || asfd->write_str(asfd, cmd, path)
	  || ((cmd==CMD_HARD_LINK || cmd==CMD_SOFT_LINK)
		&& asfd->write_str(asfd, cmd, link)))
			return -1;
	cntr_add_phase1(conf->cntr, cmd, 1);
	return 0;
}

static int maybe_send_extrameta(struct asfd *asfd, const char *path, char cmd,
	struct sbuf *sb, struct conf *conf, int symbol)
{
	if(!has_extrameta(path, cmd)) return 0;
	return usual_stuff(asfd, conf, path, NULL, sb, symbol);
}

static int ft_err(struct asfd *asfd,
	struct conf *conf, FF_PKT *ff, const char *msg)
{
	return logw(asfd, conf, _("Err: %s %s: %s"), msg,
		ff->fname, strerror(errno));
}

static int do_to_server(struct asfd *asfd,
	struct conf *conf, FF_PKT *ff, struct sbuf *sb,
	char cmd, int compression) 
{
	sb->compression=compression;
	sb->statp=ff->statp;
	attribs_encode(sb);

#ifdef HAVE_WIN32
	if(conf->split_vss && !conf->strip_vss
	  && maybe_send_extrameta(asfd, ff->fname, cmd, sb, conf, metasymbol))
		return -1;
#endif

	if(usual_stuff(asfd, conf, ff->fname, ff->link, sb, cmd)) return -1;

	if(ff->type==FT_REG)
		cntr_add_val(conf->cntr, CMD_BYTES_ESTIMATED,
			(unsigned long long)ff->statp.st_size, 0);
#ifdef HAVE_WIN32
	if(conf->split_vss && !conf->strip_vss
	// FIX THIS: May have to check that it is not a directory here.
	  && !S_ISDIR(sb->statp.st_mode) // does this work?
	  && maybe_send_extrameta(asfd,
		ff->fname, cmd, sb, conf, vss_trail_symbol))
			return -1;
	return 0;
#else
	return maybe_send_extrameta(asfd, ff->fname, cmd, sb, conf, metasymbol);
#endif
}

static int to_server(struct asfd *asfd, struct conf *conf, FF_PKT *ff,
	struct sbuf *sb, char cmd)
{
	return do_to_server(asfd, conf, ff, sb, cmd, conf->compression);
}

int send_file(struct asfd *asfd, FF_PKT *ff, bool top_level, struct conf *conf)
{
	static struct sbuf *sb=NULL;

	if(!sb && !(sb=sbuf_alloc(conf))) return -1;

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
			return logw(asfd, conf,
				"File name too long (%lu > %lu): %s",
				ff->flen, server_name_max, ff->fname);
	}

#ifdef HAVE_WIN32
	if(ff->winattr & FILE_ATTRIBUTE_ENCRYPTED)
	{
		if(ff->type==FT_REG
		  || ff->type==FT_DIR)
			return to_server(asfd, conf, ff, sb, CMD_EFS_FILE);
		return logw(asfd, conf, "EFS type %d not yet supported: %s",
			ff->type, ff->fname);
	}
#endif

	switch(ff->type)
	{
		case FT_REG:
		case FT_RAW:
		case FT_FIFO:
			return do_to_server(asfd, conf, ff, sb, filesymbol,
				in_exclude_comp(conf->excom,
					ff->fname, conf->compression));
		case FT_DIR:
		case FT_REPARSE:
		case FT_JUNCTION:
			return to_server(asfd, conf, ff, sb, dirsymbol);
		case FT_LNK_S:
			return to_server(asfd, conf, ff, sb, CMD_SOFT_LINK);
		case FT_LNK_H:
			return to_server(asfd, conf, ff, sb, CMD_HARD_LINK);
		case FT_SPEC:
			return to_server(asfd, conf, ff, sb, CMD_SPECIAL);
		case FT_NOFSCHG:
			return logw(asfd, conf, "Dir: %s [will not descend: "
				"file system change not allowed]\n", ff->fname);
		case FT_NOFOLLOW:
			return ft_err(asfd, conf, ff, "Could not follow link");
		case FT_NOSTAT:
			return ft_err(asfd, conf, ff, "Could not stat");
		case FT_NOOPEN:
			return ft_err(asfd, conf, ff, "Could not open directory");
		default:
			return logw(asfd, conf,
				_("Err: Unknown file type %d: %s"),
				ff->type, ff->fname);
	}
}

int backup_phase1_client(struct asfd *asfd,
	struct conf *conf, long name_max, int estimate)
{
	int ret=-1;
	FF_PKT *ff=NULL;
	struct strlist *l=NULL;

	// First, tell the server about everything that needs to be backed up.

	logp("Phase 1 begin (file system scan)\n");

	// Encryption not yet supported in burp2.
	if(conf->protocol==PROTO_BURP1
	  && conf->encryption_password)
	{
		filesymbol=CMD_ENC_FILE;
		metasymbol=CMD_ENC_METADATA;
#ifdef HAVE_WIN32
		metasymbol=CMD_ENC_VSS;
		vss_trail_symbol=CMD_ENC_VSS_T;
#endif
	}
#ifdef HAVE_WIN32
	dirsymbol=filesymbol;
#endif

	if(!(ff=find_files_init())) goto end;
	server_name_max=name_max;
	for(l=conf->startdir; l; l=l->next) if(l->flag)
		if(find_files_begin(asfd, ff, conf, l->path)) goto end;
	ret=0;
end:
	cntr_print_end_phase1(conf->cntr);
	if(ret) logp("Error in phase 1\n");
	logp("Phase 1 end (file system scan)\n");
	find_files_free(ff);

	return ret;
}
