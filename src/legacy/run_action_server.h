#ifndef _RUN_ACTION_SERVER_LEGACY_H
#define _RUN_ACTION_SERVER_LEGACY_H

extern int run_action_server_legacy(struct sdirs *dirs, struct config *cconf,
	struct iobuf *rbuf,
	const char *incexc, int srestore, char **gotlock, int *timer_ret);

#endif
