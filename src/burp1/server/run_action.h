#ifndef _RUN_ACTION_SERVER_LEGACY_H
#define _RUN_ACTION_SERVER_LEGACY_H

extern int check_for_rubble_burp1(struct sdirs *sdirs, struct conf *cconf,
	const char *incexc, int *resume);
extern int do_backup_server_burp1(struct sdirs *sdirs, struct conf *cconf,
        const char *incexc, int resume);

#endif
