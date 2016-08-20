#ifndef _RESTORE_CLIENT_PROTOCOL1_H
#define _RESTORE_CLIENT_PROTOCOL1_H

#include "action.h"
#include "bfile.h"
#include "sbuf.h"

int restore_switch_protocol1(struct asfd *asfd, struct sbuf *sb,
	const char *fullpath, enum action act,
	BFILE *bfd, int vss_restore, struct cntr *cntr,
	const char *encryption_password);

#endif
