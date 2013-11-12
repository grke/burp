#ifndef BACKUP_SERVER_H
#define BACKUP_SERVER_H

extern int do_backup_server(struct sdirs *sdirs, struct config *cconf,
	const char *client, const char *cversion, const char *incexc);

#endif
