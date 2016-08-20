#ifndef _CSTAT_H
#define _CSTAT_H

#include "conf.h"
#include "cntr.h"

#define RUN_STATUS_STR_IDLE		"idle"
#define RUN_STATUS_STR_CLIENT_CRASHED	"c crashed"
#define RUN_STATUS_STR_SERVER_CRASHED	"s crashed"
#define RUN_STATUS_STR_RUNNING		"running"

typedef enum run_status
{
	RUN_STATUS_UNSET=0,

	RUN_STATUS_IDLE,
	RUN_STATUS_RUNNING,
	RUN_STATUS_CLIENT_CRASHED,
	RUN_STATUS_SERVER_CRASHED
} run_status;

struct cstat
{
	char *name;
	char *conffile;
	struct strlist *labels;
	time_t conf_mtime;
	struct cntr *cntr; // Set from the parent process.
	enum run_status run_status;
	// From the perspective of the server child, whether the connected
	// client is allowed to view this client.
	uint8_t permitted;

	// When the mtime of conffile changes, the following get reloaded.
	// Declared sdirs as void so that cstat can be declared for both
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
extern int cstat_init_with_cntr(struct cstat *cstat,
        const char *name, const char *clientconfdir);
extern void cstat_free(struct cstat **cstat);
extern void cstat_list_free(struct cstat **clist);
extern void cstat_add_to_list(struct cstat **clist, struct cstat *cnew);

extern const char *run_status_to_str(struct cstat *cstat);
extern run_status run_str_to_status(const char *str);

extern struct cstat *cstat_get_by_name(struct cstat *clist, const char *name);

#endif
