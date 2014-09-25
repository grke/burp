#ifndef BACKUP_PHASE1_SERVER_H
#define BACKUP_PHASE1_SERVER_H

extern int backup_phase1_server(const char *phase1data, const char *client,
	struct cntr *p1cntr, struct cntr *cntr, struct config *cconf);
extern int do_resume(gzFile p1zp,
	const char *phase2data, const char *unchangeddata,
	struct dpth *dpth, struct config *cconf,
	const char *client, struct cntr *p1cntr, struct cntr *cntr);

#endif
