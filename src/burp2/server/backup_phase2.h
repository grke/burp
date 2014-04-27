#ifndef _BACKUP_PHASE2_SERVER_H
#define _BACKUP_PHASE2_SERVER_H

extern int backup_phase2_server(struct async *as, struct sdirs *sdirs,
	const char *manifest_dir, struct async *chas,
	int resume, struct conf *conf);

#endif
