#ifndef _RUN_ACTION_SERVER_LEGACY_H
#define _RUN_ACTION_SERVER_LEGACY_H

extern int run_action_server_legacy(struct config *cconf, struct sdirs *sdirs,
	struct iobuf *rbuf, const char *incexc, int srestore, int *timer_ret);

#endif
