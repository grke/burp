#ifndef _PROG_H
#define _PROG_H

#ifdef HAVE_LIBZ
#include <zlib.h>                     /* compression headers */
#endif

enum action
{
	ACTION_BACKUP=0,
	ACTION_RESTORE,
	ACTION_VERIFY,
	ACTION_LIST,
	ACTION_LONG_LIST,
	ACTION_BACKUP_TIMED,
	ACTION_STATUS,
	ACTION_STATUS_SNAPSHOT,
	ACTION_ESTIMATE,
};

#include "find.h"
#include "log.h"

extern int setup_signals(int oldmax_children, int max_children, int oldmax_status_children, int max_status_children);
extern int reload(struct config *conf, const char *configfile, bool firsttime, int oldmax_children, int oldmax_status_children);

extern int server(struct config *conf, const char *configfile,
	int generate_ca_only);
extern int client(struct config *conf, enum action act, const char *restore_client);

#endif // _PROG_H
