#ifndef _BURP1_BACKUP_PHASE2_SERVER_H
#define _BURP1_BACKUP_PHASE2_SERVER_H

extern int backup_phase2_server(struct asfd *asfd, struct sdirs *sdirs,
	const char *incexc, int resume, struct conf *cconf);

#endif
