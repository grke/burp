#ifndef _BACKUP_CLIENT_H
#define _BACKUP_CLIENT_H

extern int do_backup_client(struct asfd *asfd,
	struct conf **confs, enum action act, int resume);

#endif
