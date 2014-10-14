#ifndef _CSTAT_H
#define _CSTAT_H

#include "include.h"

#define STATUS_STR_IDLE			"idle"
#define STATUS_STR_CLIENT_CRASHED	"c crashed"
#define STATUS_STR_SERVER_CRASHED	"s crashed"
#define STATUS_STR_RUNNING		"running"
#define STATUS_STR_SCANNING		"scanning"
#define STATUS_STR_BACKUP		"backup"
#define STATUS_STR_MERGING		"merging"
#define STATUS_STR_SHUFFLING		"shuffling"
#define STATUS_STR_LISTING		"listing"
#define STATUS_STR_RESTORING		"restoring"
#define STATUS_STR_VERIFYING		"verifying"
#define STATUS_STR_DELETING		"deleting"

enum cstat_status
{
	STATUS_UNSET=0,

	STATUS_IDLE,
	STATUS_RUNNING,
	STATUS_CLIENT_CRASHED,
	STATUS_SERVER_CRASHED,

	STATUS_SCANNING,
	STATUS_BACKUP,
	STATUS_MERGING,
	STATUS_SHUFFLING,
	STATUS_LISTING,
	STATUS_RESTORING,
	STATUS_VERIFYING,
	STATUS_DELETING
};

struct cstat
{
	char *name;
	char *conffile;
	time_t conf_mtime;
	char *running_detail; // set from the parent process
	enum cstat_status status;
	// From the perspective of the server child, whether the connected
	// client is allowed to view this client.
	uint8_t permitted;

	// When the mtime of conffile changes, the following get reloaded
	// sdirs declared as void so that cstat can be declared for both
	// client and server. Server side will have to cast it.
	void *sdirs;
	time_t clientdir_mtime;
	time_t lockfile_mtime;

	struct bu *bu; // Backup list.
	enum protocol protocol;

	struct cstat *prev;
	struct cstat *next;
};

extern struct cstat *cstat_alloc(void);
extern int cstat_init(struct cstat *cstat,
        const char *name, const char *clientconfdir);
extern void cstat_free(struct cstat **cstat);
extern int cstat_add_to_list(struct cstat **clist, struct cstat *cnew);

extern const char *cstat_status_to_str(struct cstat *cstat);
extern cstat_status cstat_str_to_status(const char *str);

extern struct cstat *cstat_get_by_name(struct cstat *clist, const char *name);

#endif
