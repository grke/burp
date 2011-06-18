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

static char filesymbol='f';

static int send_file(FF_PKT *ff, bool top_level, struct config *conf, struct cntr *cntr)
{
   char msg[128]="";
   char attribs[MAXSTRING];

   if(!file_is_included(conf->incexcdir, conf->iecount, ff->fname)) return 0;

 //  logp("%d: %s\n", ff->type, ff->fname);

   switch (ff->type) {
   case FT_LNKSAVED:
        //printf("Lnka: %s -> %s\n", ff->fname, ff->link);
   	encode_stat(attribs, &ff->statp, has_extrameta(ff->fname));
	if(async_write_str('r', attribs)
	  || async_write_str('L', ff->fname)
	  || async_write_str('L', ff->link))
		return -1;
	do_filecounter(cntr, 'L', 1);
      break;
   case FT_FIFO:
   case FT_REGE:
   case FT_REG:
      encode_stat(attribs, &ff->statp, has_extrameta(ff->fname));
      if(async_write_str('r', attribs)
	|| async_write_str(filesymbol, ff->fname))
		return -1;
	do_filecounter(cntr, filesymbol, 1);
      break;
   case FT_LNK:
	//printf("link: %s -> %s\n", ff->fname, ff->link);
   	encode_stat(attribs, &ff->statp, has_extrameta(ff->fname));
	if(async_write_str('r', attribs)
	  || async_write_str('l', ff->fname)
	  || async_write_str('l', ff->link))
		return -1;
	do_filecounter(cntr, 'l', 1);
      break;
   case FT_DIREND:
      return 0;
   case FT_NOFSCHG:
   case FT_INVALIDFS:
   case FT_INVALIDDT:
   case FT_DIRBEGIN:
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
		logw(cntr, "%s", msg);
	 }
	 else
	 {
		encode_stat(attribs, &ff->statp, has_extrameta(ff->fname));
	      	if(async_write_str('r', attribs)) return -1;
#if defined(WIN32_VSS)
		if(async_write_str(filesymbol, ff->fname)) return -1;
		do_filecounter(cntr, filesymbol, 1);
#else
		if(async_write_str('d', ff->fname)) return -1;
		do_filecounter(cntr, 'd', 1);
#endif
	 }
	}
      break;
   case FT_SPEC: // special file - fifo, socket, device node...
      encode_stat(attribs, &ff->statp, has_extrameta(ff->fname));
      if(async_write_str('r', attribs)
	  || async_write_str('s', ff->fname))
		return -1;
      do_filecounter(cntr, 's', 1);
      break;
   case FT_NOACCESS:
      logw(cntr, _("Err: Could not access %s: %s"), ff->fname, strerror(errno));
      break;
   case FT_NOFOLLOW:
      logw(cntr, _("Err: Could not follow ff->link %s: %s"), ff->fname, strerror(errno));
      break;
   case FT_NOSTAT:
      logw(cntr, _("Err: Could not stat %s: %s"), ff->fname, strerror(errno));
      break;
   case FT_NOCHG:
      logw(cntr, _("Skip: File not saved. No change. %s"), ff->fname);
      break;
   case FT_ISARCH:
      logw(cntr, _("Err: Attempt to backup archive. Not saved. %s"), ff->fname);
      break;
   case FT_NOOPEN:
      logw(cntr, _("Err: Could not open directory %s: %s"), ff->fname, strerror(errno));
      break;
   case FT_REPARSE:
      logw(cntr, _("Err: Windows reparse point: %s"), ff->fname);
      break;
   case FT_RAW:
      logw(cntr, _("Err: Raw partition: %s"), ff->fname);
      break;
   default:
      logw(cntr, _("Err: Unknown file ff->type %d: %s"), ff->type, ff->fname);
      break;
   }
   return 0;
}

int backup_phase1_client(struct config *conf, struct cntr *cntr)
{
	int sd=0;
	int ret=0;
	FF_PKT *ff=NULL;

	// First, tell the server about everything that needs to be backed up.

	logp("Phase 1 begin (file system scan)\n");
        reset_filecounter(cntr);

	if(conf->encryption_password) filesymbol='y';

logp("before init find files\n");
	ff=init_find_files();
logp("after init find files\n");
	for(; sd < conf->sdcount; sd++)
	{
		if(conf->startdir[sd]->flag)
		{
			if((ret=find_files(ff, conf,
				conf->startdir[sd]->path, cntr, send_file)))
					break;
		}
	}
	term_find_files(ff);

	end_filecounter(cntr, 1, ACTION_BACKUP);
	if(ret) logp("Error in phase 1\n");
	logp("Phase 1 end (file system scan)\n");

	return ret;
}
