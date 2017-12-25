#ifndef _RESTORE_CLIENT_PROTOCOL2_H
#define _RESTORE_CLIENT_PROTOCOL2_H

struct sbuf;

#include "../../protocol2/blk.h"

extern int write_protocol2_data(struct asfd *asfd,
        struct BFILE *bfd, struct blk *blk, int vss_restore);
extern int restore_switch_protocol2(struct asfd *asfd, struct sbuf *sb,
	const char *fullpath, enum action act,
	struct BFILE *bfd, int vss_restore, struct cntr *cntr);

#endif
