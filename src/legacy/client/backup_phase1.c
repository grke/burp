#include "include.h"

static char filesymbol=CMD_FILE;
#ifdef HAVE_WIN32
static char metasymbol=CMD_VSS;
static char vss_trail_symbol=CMD_VSS_T;
#else
static char metasymbol=CMD_METADATA;
#endif

static long server_name_max;

static int maybe_send_extrameta(const char *path, char cmd, struct sbufl *sb, struct config *conf)
{
	if(has_extrameta(path, cmd))
	{
		if(async_write(&sb->attr)
		  || async_write_str(metasymbol, path))
			return -1;
		do_filecounter(conf->p1cntr, metasymbol, 1);
	}
	return 0;
}

// FIX THIS: make the find file stuff return an sb - requires the burp2 stuff
// to be compatible with the old stuff.
static int encode_stat_w(struct sbufl *sb, FF_PKT *ff, int compression)
{
	sb->winattr=ff->winattr;
	sb->compression=compression;
	memcpy(&sb->statp, &ff->statp, sizeof(sb->statp));
	return sbufl_attribs_encode(sb);
}

int send_file_legacy(FF_PKT *ff, bool top_level, struct config *conf)
{
   char msg[128]="";
   static struct sbufl sb;

   if(!file_is_included(conf, ff->fname, top_level)) return 0;

  if(server_name_max)
  {
	  if(top_level)
	  {
		char *cp=NULL;
		// Need to figure out the length of the filename component.
		if((cp=strrchr(ff->fname, '/'))) ff->flen=strlen(cp+1);
		else ff->flen=strlen(ff->fname);	
	  }
	  if(ff->flen>server_name_max)
	  {
		logw(conf->p1cntr, "File name too long (%lu > %lu): %s",
			ff->flen, server_name_max, ff->fname);
		return 0;
	  }
  }


#ifdef HAVE_WIN32
	if(ff->winattr & FILE_ATTRIBUTE_ENCRYPTED)
	{
		if(ff->type==FT_REG
		  || ff->type==FT_DIR)
		{
			if(encode_stat_w(&sb, ff, conf->compression)
			  || async_write(sb.attr)
			  || async_write_str(CMD_EFS_FILE, ff->fname))
				return -1;
			do_filecounter(conf->p1cntr, CMD_EFS_FILE, 1);
			if(ff->type==FT_REG)
				do_filecounter_bytes(conf->p1cntr,
					(unsigned long long)ff->statp.st_size);
			return 0;
		}
		else
		{
			// Hopefully, here is never reached.
			logw(conf->p1cntr, "EFS type %d not yet supported: %s",
				ff->type,
				ff->fname);
			return 0;
		}
	}
#endif

   switch (ff->type) {
#ifndef HAVE_WIN32
   case FT_LNK_H:
        //printf("Lnka: %s -> %s\n", ff->fname, ff->link);
   	if(encode_stat_w(&sb, ff, conf->compression)
	  || async_write(&sb.attr)
	  || async_write_str(CMD_HARD_LINK, ff->fname)
	  || async_write_str(CMD_HARD_LINK, ff->link))
		return -1;
	do_filecounter(conf->p1cntr, CMD_HARD_LINK, 1);
	// At least FreeBSD 8.2 can have different xattrs on hard links.
	if(maybe_send_extrameta(ff->fname, CMD_HARD_LINK, &sb, conf))
		return -1;
#endif
      break;
   case FT_RAW:
   case FT_FIFO:
   case FT_REG:
      if(encode_stat_w(&sb, ff,
		in_exclude_comp(conf->excom, ff->fname, conf->compression)))
			return -1;
#ifdef HAVE_WIN32
      if(conf->split_vss && !conf->strip_vss
	&& maybe_send_extrameta(ff->fname, filesymbol, attribs, conf))
		return -1;
#endif
      if(async_write(&sb.attr)
	|| async_write_str(filesymbol, ff->fname))
		return -1;
      do_filecounter(conf->p1cntr, filesymbol, 1);
      if(ff->type==FT_REG)
	do_filecounter_bytes(conf->p1cntr, (unsigned long long)ff->statp.st_size);
#ifdef HAVE_WIN32
      // Possible trailing VSS meta data
      if(conf->split_vss && !conf->strip_vss)
      {
	if(async_write_str(CMD_ATTRIBS, attribs)
	 || async_write_str(vss_trail_symbol, ff->fname))
		return -1;
        do_filecounter(conf->p1cntr, vss_trail_symbol, 1);
      }
#else
      if(maybe_send_extrameta(ff->fname, filesymbol, &sb, conf))
		return -1;
#endif
      break;
#ifndef HAVE_WIN32
   case FT_LNK_S:
	//printf("link: %s -> %s\n", ff->fname, ff->link);
   	if(encode_stat_w(&sb, ff, conf->compression))
		return -1;
        if(conf->split_vss && !conf->strip_vss
	  && maybe_send_extrameta(ff->fname, CMD_SOFT_LINK, &sb, conf))
		return -1;
	if(async_write(&sb.attr)
	  || async_write_str(CMD_SOFT_LINK, ff->fname)
	  || async_write_str(CMD_SOFT_LINK, ff->link))
		return -1;
	do_filecounter(conf->p1cntr, CMD_SOFT_LINK, 1);
        if(maybe_send_extrameta(ff->fname, CMD_SOFT_LINK, &sb, conf))
		return -1;
#endif
      break;
   case FT_NOFSCHG:
   case FT_DIR:
   case FT_REPARSE:
   case FT_JUNCTION:
	{
         char errmsg[100] = "";
         if (ff->type == FT_NOFSCHG)
            snprintf(errmsg, sizeof(errmsg), _("\t[will not descend: file system change not allowed]"));
	 if(*errmsg)
	 {
		snprintf(msg, sizeof(msg),
			"%s%s%s\n", "Dir: ", ff->fname, errmsg);
		logw(conf->p1cntr, "%s", msg);
	 }
	 else
	 {
		if(encode_stat_w(&sb, ff, conf->compression))
			return -1;
#ifdef HAVE_WIN32
		if(conf->split_vss || conf->strip_vss)
		{
			if(!conf->strip_vss
			  && maybe_send_extrameta(ff->fname,
				CMD_DIRECTORY, attribs, conf)) return -1;
	      		if(async_write_str(CMD_ATTRIBS, attribs)) return -1;
			if(async_write_str(CMD_DIRECTORY, ff->fname)) return -1;
			do_filecounter(conf->p1cntr, CMD_DIRECTORY, 1);
		}
		else
		{
	      		if(async_write_str(CMD_ATTRIBS, attribs)) return -1;
			if(async_write_str(filesymbol, ff->fname)) return -1;
			do_filecounter(conf->p1cntr, filesymbol, 1);
		}
#else
	      	if(async_write(&sb.attr)
		  || async_write_str(CMD_DIRECTORY, ff->fname)) return -1;
		do_filecounter(conf->p1cntr, CMD_DIRECTORY, 1);
        	if(maybe_send_extrameta(ff->fname, CMD_DIRECTORY,
			&sb, conf)) return -1;
#endif
	 }
	}
      break;
#ifndef HAVE_WIN32
   case FT_SPEC: // special file - fifo, socket, device node...
      if(encode_stat_w(&sb, ff, conf->compression)
	|| async_write(&sb.attr)
	|| async_write_str(CMD_SPECIAL, ff->fname))
		return -1;
      do_filecounter(conf->p1cntr, CMD_SPECIAL, 1);
      if(maybe_send_extrameta(ff->fname, CMD_SPECIAL, &sb, conf))
		return -1;
#endif
      break;
   case FT_NOFOLLOW:
      logw(conf->p1cntr, _("Err: Could not follow ff->link %s: %s"), ff->fname, strerror(errno));
      break;
   case FT_NOSTAT:
      logw(conf->p1cntr, _("Err: Could not stat %s: %s"), ff->fname, strerror(errno));
      break;
   case FT_NOOPEN:
      logw(conf->p1cntr, _("Err: Could not open directory %s: %s"), ff->fname, strerror(errno));
      break;
   default:
      logw(conf->p1cntr, _("Err: Unknown file ff->type %d: %s"), ff->type, ff->fname);
      break;
   }
   return 0;
}

int backup_phase1_client_legacy(struct config *conf, long name_max, int estimate)
{
	int ret=0;
	FF_PKT *ff=NULL;
	struct strlist *l;

	// First, tell the server about everything that needs to be backed up.

	logp("Phase 1 begin (file system scan)\n");

	if(conf->encryption_password)
	{
		filesymbol=CMD_ENC_FILE;
#ifdef HAVE_WIN32
		metasymbol=CMD_ENC_VSS;
		vss_trail_symbol=CMD_ENC_VSS_T;
#else
		metasymbol=CMD_ENC_METADATA;
#endif
	}

	ff=find_files_init();
	server_name_max=name_max;
	for(l=conf->startdir; l; l=l->next) if(l->flag)
		if((ret=find_files_begin(ff, conf, l->path)))
			break;
	find_files_free(ff);

	print_endcounter(conf->p1cntr);
	//print_filecounters(conf, ACTION_BACKUP);
	if(ret) logp("Error in phase 1\n");
	logp("Phase 1 end (file system scan)\n");

	return ret;
}
