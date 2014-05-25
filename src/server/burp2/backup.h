#ifndef BACKUP_SERVER_H
#define BACKUP_SERVER_H

extern int open_log(struct asfd *asfd,
	const char *realworking, struct conf *cconf);

extern int do_backup_server_burp2(struct async *as,
	struct sdirs *sdirs, struct conf *cconf,
	const char *incexc, int resume);

#endif
