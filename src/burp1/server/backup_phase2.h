#ifndef _BURP1_BACKUP_PHASE2_SERVER_H
#define _BURP1_BACKUP_PHASE2_SERVER_H

extern int backup_phase2_server(struct async *as,
	struct sdirs *sdirs, struct conf *cconf,
	gzFile *cmanfp, struct dpthl *dpthl, int resume);

#endif
