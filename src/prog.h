#ifndef _PROG_H
#define _PROG_H

#ifdef HAVE_LIBZ
#include <zlib.h>                     /* compression headers */
#endif

#include "conf.h"
#include "log.h"

extern int setup_signals(int oldmax_children, int max_children, int oldmax_status_children, int max_status_children);
extern int reload(struct config *conf, const char *configfile, bool firsttime, int oldmax_children, int oldmax_status_children);

#endif // _PROG_H
