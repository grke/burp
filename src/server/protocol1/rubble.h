#ifndef _RUBBLE_PROTOCOL1_H
#define _RUBBLE_PROTOCOL1_H

extern int check_for_rubble_protocol1(struct asfd *asfd,
	struct sdirs *sdirs, const char *incexc,
	int *resume, struct conf **cconfs);

#endif
