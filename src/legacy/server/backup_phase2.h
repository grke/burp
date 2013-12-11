#ifndef _BACKUP_PHASE2_SERVER_H
#define _BACKUP_PHASE2_SERVER_H

extern int backup_phase2_server(struct sdirs *sdirs, struct config *cconf,
	gzFile *cmanfp, struct dpth *dpth, int resume);

#endif
