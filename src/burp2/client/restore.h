#ifndef _RESTORE_CLIENT_H
#define _RESTORE_CLIENT_H

int do_restore_client(struct asfd *asfd,
	struct conf *conf, enum action act, int vss_restore);

#endif
