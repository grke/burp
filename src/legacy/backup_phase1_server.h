#ifndef _BACKUP_PHASE1_SERVER_H
#define _BACKUP_PHASE1_SERVER_H

extern int backup_phase1_server(struct sdirs *sdirs, struct config *cconf);
extern int do_resume(gzFile p1zp, FILE *p2fp, FILE *ucfp, struct dpth *dpth,
	struct config *cconf);

#endif
