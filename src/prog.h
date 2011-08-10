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
	ACTION_STATUS
};

#include "find.h"
#include "log.h"

extern int server_reload(struct config *conf, const char *configfile, char **logfile, bool firsttime, int oldmax_children);

extern int server(struct config *conf, const char *configfile, int forking,
	int daemon, char **logfile);
extern int client(struct config *conf, enum action act, const char *backup,
	const char *restoreprefix, const char *regex, int forceoverwrite);

#endif // _PROG_H
