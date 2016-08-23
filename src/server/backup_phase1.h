#ifndef _BACKUP_PHASE1_SERVER_H
#define _BACKUP_PHASE1_SERVER_H

struct async;
struct conf;
struct sdirs;

extern int backup_phase1_server_all(struct async *as,
	struct sdirs *sdirs, struct conf **confs);

#endif
