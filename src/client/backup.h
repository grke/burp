#ifndef _BACKUP_CLIENT_H
#define _BACKUP_CLIENT_H

extern int do_backup_client(struct config *conf, enum action act,
	long name_max, int resume);

#endif
