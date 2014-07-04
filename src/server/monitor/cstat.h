#ifndef _CSTAT_H
#define _CSTAT_H

#include "include.h"

// FIX THIS: should probably use struct sdirs.
// And should maybe use a linked list instead of a stupid array.
struct cstat
{
	char *name;
	char *conffile;
	time_t conf_mtime;
	char *running_detail; // set from the parent process
	char status;

	// When the mtime of conffile changes, the following get reloaded
	char *basedir;
	time_t basedir_mtime;
	char *working;
	char *current;
	char *timestamp;
	char *lockfile;
	time_t lockfile_mtime;
	struct bu *bu; // backup list
};

extern int cstat_load_data_from_disk(struct cstat ***clist,
	int *clen, struct conf *conf);
extern int cstat_set_status(struct cstat *cstat);
extern int cstat_set_backup_list(struct cstat *cstat);
extern const char *cstat_status_to_str(struct cstat *cstat);

#endif
