#ifndef BACKUP_SERVER_H
#define BACKUP_SERVER_H

extern int open_log(const char *realworking, struct config *cconf);

extern int do_backup_server(struct sdirs *sdirs, struct config *cconf,
	const char *incexc);

#endif
