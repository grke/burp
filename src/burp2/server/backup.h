#ifndef BACKUP_SERVER_H
#define BACKUP_SERVER_H

extern int open_log(const char *realworking, struct conf *cconf);

extern int do_backup_server(struct sdirs *sdirs, struct conf *cconf,
	const char *incexc, int resume);

#endif
