#ifndef _RUN_ACTION_SERVER_LEGACY_H
#define _RUN_ACTION_SERVER_LEGACY_H

extern int check_for_rubble_legacy(struct sdirs *sdirs, struct config *cconf,
	const char *incexc, int *resume);
extern int do_backup_server_legacy(struct sdirs *sdirs, struct config *cconf,
        const char *incexc, int resume);

#endif
