#include "burp.h"
#include "prog.h"
#include "msg.h"
#include "rs_buf.h"
#include "lock.h"
#include "handy.h"
#include "asyncio.h"
#include "counter.h"
#include "extrameta.h"
#include "backup_phase1_client.h"

static char filesymbol=CMD_FILE;
static char metasymbol=CMD_METADATA;

static int maybe_send_extrameta(const char *path, char cmd, const char *attribs, struct cntr *p1cntr)
{
	if(has_extrameta(path, cmd))
	{
		if(async_write_str(CMD_STAT, attribs)
		  || async_write_str(metasymbol, path))
			return -1;
		do_filecounter(p1cntr, metasymbol, 1);
	}
	return 0;
}

int send_file(FF_PKT *ff, bool top_level, struct config *conf, struct cntr *p1cntr)
{
   char msg[128]="";
   char attribs[MAXSTRING];

   if(!file_is_included(conf->incexcdir, conf->iecount,
	conf->excext, conf->excount, ff->fname)) return 0;
#ifdef HAVE_WIN32
	if(ff->winattr & FILE_ATTRIBUTE_ENCRYPTED)
	{
		if(ff->type!=FT_DIREND)
			logw(p1cntr, "EFS not yet supported: %s", ff->fname);
		return 0;
	}
#endif

   //logp("%d: %s\n", ff->type, ff->fname);

   switch (ff->type) {
   case FT_LNKSAVED:
        //printf("Lnka: %s -> %s\n", ff->fname, ff->link);
   	encode_stat(attribs, &ff->statp, ff->winattr);
	if(async_write_str(CMD_STAT, attribs)
	  || async_write_str(CMD_HARD_LINK, ff->fname)
	  || async_write_str(CMD_HARD_LINK, ff->link))
		return -1;
	do_filecounter(p1cntr, CMD_HARD_LINK, 1);
	// At least FreeBSD 8.2 can have different xattrs on hard links.
	if(maybe_send_extrameta(ff->fname, CMD_HARD_LINK, attribs, p1cntr))
		return -1;
      break;
   case FT_FIFO:
   case FT_REGE:
   case FT_REG:
      encode_stat(attribs, &ff->statp, ff->winattr);
      if(async_write_str(CMD_STAT, attribs)
	|| async_write_str(filesymbol, ff->fname))
		return -1;
      do_filecounter(p1cntr, filesymbol, 1);
      if(ff->type==FT_REG)
	do_filecounter_bytes(p1cntr, (unsigned long long)ff->statp.st_size);
      if(maybe_send_extrameta(ff->fname, filesymbol, attribs, p1cntr))
		return -1;
      break;
   case FT_LNK:
	//printf("link: %s -> %s\n", ff->fname, ff->link);
   	encode_stat(attribs, &ff->statp, ff->winattr);
	if(async_write_str(CMD_STAT, attribs)
	  || async_write_str(CMD_SOFT_LINK, ff->fname)
	  || async_write_str(CMD_SOFT_LINK, ff->link))
		return -1;
	do_filecounter(p1cntr, CMD_SOFT_LINK, 1);
        if(maybe_send_extrameta(ff->fname, CMD_SOFT_LINK, attribs, p1cntr))
		return -1;
      break;
   case FT_DIREND:
      return 0;
   case FT_NOFSCHG:
   case FT_INVALIDFS:
   case FT_INVALIDDT:
   case FT_DIRBEGIN:
   case FT_REPARSE:
   case FT_JUNCTION:
	{
         char errmsg[100] = "";
         if (ff->type == FT_NOFSCHG)
            snprintf(errmsg, sizeof(errmsg), _("\t[will not descend: file system change not allowed]"));
         else if (ff->type == FT_INVALIDFS)
            snprintf(errmsg, sizeof(errmsg), _("\t[will not descend: disallowed file system]"));
         else if (ff->type == FT_INVALIDDT)
            snprintf(errmsg, sizeof(errmsg), _("\t[will not descend: disallowed drive type]"));
	 if(*errmsg)
	 {
		snprintf(msg, sizeof(msg),
			"%s%s%s\n", "Dir: ", ff->fname, errmsg);
		logw(p1cntr, "%s", msg);
	 }
	 else
	 {
		encode_stat(attribs, &ff->statp, ff->winattr);
	      	if(async_write_str(CMD_STAT, attribs)) return -1;
#if defined(WIN32_VSS)
		if(async_write_str(filesymbol, ff->fname)) return -1;
		do_filecounter(p1cntr, filesymbol, 1);
#else
		if(async_write_str(CMD_DIRECTORY, ff->fname)) return -1;
		do_filecounter(p1cntr, CMD_DIRECTORY, 1);
        	if(maybe_send_extrameta(ff->fname, CMD_DIRECTORY,
			attribs, p1cntr)) return -1;
#endif
	 }
	}
      break;
   case FT_SPEC: // special file - fifo, socket, device node...
      encode_stat(attribs, &ff->statp, ff->winattr);
      if(async_write_str(CMD_STAT, attribs)
	  || async_write_str(CMD_SPECIAL, ff->fname))
		return -1;
      do_filecounter(p1cntr, CMD_SPECIAL, 1);
      if(maybe_send_extrameta(ff->fname, CMD_SPECIAL, attribs, p1cntr))
		return -1;
      break;
   case FT_NOACCESS:
      logw(p1cntr, _("Err: Could not access %s: %s"), ff->fname, strerror(errno));
      break;
   case FT_NOFOLLOW:
      logw(p1cntr, _("Err: Could not follow ff->link %s: %s"), ff->fname, strerror(errno));
      break;
   case FT_NOSTAT:
      logw(p1cntr, _("Err: Could not stat %s: %s"), ff->fname, strerror(errno));
      break;
   case FT_NOCHG:
      logw(p1cntr, _("Skip: File not saved. No change. %s"), ff->fname);
      break;
   case FT_ISARCH:
      logw(p1cntr, _("Err: Attempt to backup archive. Not saved. %s"), ff->fname);
      break;
   case FT_NOOPEN:
      logw(p1cntr, _("Err: Could not open directory %s: %s"), ff->fname, strerror(errno));
      break;
   case FT_RAW:
      logw(p1cntr, _("Err: Raw partition: %s"), ff->fname);
      break;
   default:
      logw(p1cntr, _("Err: Unknown file ff->type %d: %s"), ff->type, ff->fname);
      break;
   }
   return 0;
}

int backup_phase1_client(struct config *conf, int estimate, struct cntr *p1cntr, struct cntr *cntr)
{
	int sd=0;
	int ret=0;
	FF_PKT *ff=NULL;

	// First, tell the server about everything that needs to be backed up.

	logp("Phase 1 begin (file system scan)\n");

	if(conf->encryption_password)
	{
		filesymbol=CMD_ENC_FILE;
		metasymbol=CMD_ENC_METADATA;
	}

	ff=init_find_files();
	for(; sd < conf->sdcount; sd++)
	{
		if(conf->startdir[sd]->flag)
		{
			if((ret=find_files_begin(ff, conf,
				conf->startdir[sd]->path, p1cntr)))
					break;
		}
	}
	term_find_files(ff);

	print_endcounter(p1cntr);
	//print_filecounters(p1cntr, cntr, ACTION_BACKUP);
	if(ret) logp("Error in phase 1\n");
	logp("Phase 1 end (file system scan)\n");

	return ret;
}
