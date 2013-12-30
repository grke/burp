#ifndef _RUN_ACTION_SERVER_H
#define _RUN_ACTION_SERVER_H

extern void maybe_do_notification(int status, const char *clientdir,
	const char *storagedir, const char *filename,
	const char *brv, struct config *cconf);

extern int run_action_server(struct config *cconf, struct sdirs *sdirs,
	struct iobuf *rbuf, const char *incexc, int srestore, int *timer_ret);

#endif
