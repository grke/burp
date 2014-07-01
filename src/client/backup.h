#ifndef _BACKUP_CLIENT_H
#define _BACKUP_CLIENT_H

extern int do_backup_client(struct asfd *asfd,
	struct conf *conf, enum action act, int resume);

#endif
