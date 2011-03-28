#include "burp.h"
#include "prog.h"
#include "find.h"

int32_t name_max;              /* filename max length */
int32_t path_max;              /* path name max length */

static int our_callback(FF_PKT *ff, bool top_level, struct config *conf, struct cntr *cntr);

static const int fnmode = 0;

/*
 * Initialize the find files "global" variables
 */
FF_PKT *init_find_files()
{
  FF_PKT *ff;

  ff = (FF_PKT *)malloc(sizeof(FF_PKT));
  memset(ff, 0, sizeof(FF_PKT));

   /* Get system path and filename maximum lengths */
   path_max = pathconf(".", _PC_PATH_MAX);
   if (path_max < 1024) {
      path_max = 1024;
   }

   name_max = pathconf(".", _PC_NAME_MAX);
   if (name_max < 1024) {
      name_max = 1024;
   }
   path_max++;                        /* add for EOS */
   name_max++;                        /* add for EOS */

  return ff;
}

/*
 * Call this subroutine with a callback subroutine as the first
 * argument and a packet as the second argument, this packet
 * will be passed back to the callback subroutine as the last
 * argument.
 *
 */
/* TODO: Get rid of this stupid callback stuff */
int
find_files(FF_PKT *ff, struct config *conf, char *mypath, struct cntr *cntr, int file_save(FF_PKT *ff_pkt, bool top_level, struct config *conf, struct cntr *cntr))
{
	ff->file_save = file_save;
	ff->flags = 0;
	return find_one_file(ff, conf, cntr, our_callback, mypath, (dev_t)-1, true);
}

/*
 * The code comes here for each file examined.
 * We filter the files, then call the user's callback if
 *    the file is included.
 */
static int our_callback(FF_PKT *ff, bool top_level, struct config *conf, struct cntr *cntr)
{
   if (top_level)
      return ff->file_save(ff, top_level, conf, cntr);

   switch (ff->type) {
   case FT_NOACCESS:
   case FT_NOFOLLOW:
   case FT_NOSTAT:
   case FT_NOCHG:
   case FT_ISARCH:
   case FT_NOFSCHG:
   case FT_INVALIDFS:
   case FT_INVALIDDT:
   case FT_NOOPEN:
   case FT_REPARSE:

   /* These items can be filtered */
   case FT_LNKSAVED:
   case FT_REGE:
   case FT_REG:
   case FT_LNK:
   case FT_DIRBEGIN:
   case FT_DIREND:
   case FT_RAW:
   case FT_FIFO:
   case FT_SPEC:
   case FT_DIRNOCHG:
         return ff->file_save(ff, top_level, conf, cntr);

   default:
      return -1;
   }
}


/*
 * Terminate find_files() and release
 * all allocated memory
 */
int
term_find_files(FF_PKT *ff)
{
   int hard_links;

   hard_links = term_find_one(ff);
   free(ff);
   return hard_links;
}
