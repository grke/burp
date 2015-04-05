#ifndef _RUBBLE_PROTOCOL2_H
#define _RUBBLE_PROTOCOL2_H

extern int check_for_rubble_protocol2(struct async *as,
	struct sdirs *sdirs, const char *incexc,
	int *resume, struct conf **cconfs);

#endif
