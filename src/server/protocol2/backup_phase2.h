#ifndef _BACKUP_PHASE2_SERVER_PROTOCOL2_H
#define _BACKUP_PHASE2_SERVER_PROTOCOL2_H

extern int backup_phase2_server_protocol2(struct async *as,
	struct sdirs *sdirs, int resume, struct conf **confs);

#ifdef UTEST
extern int do_backup_phase2_server_protocol2(struct async *as,
	struct asfd *chfd,
	struct sdirs *sdirs, int resume, struct conf **confs);
#endif


#endif
