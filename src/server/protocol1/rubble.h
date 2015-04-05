#ifndef _RUBBLE_PROTOCOL1_H
#define _RUBBLE_PROTOCOL1_H

// Return 1 if the backup is now finalising.
extern int check_for_rubble_protocol1(struct async *as,
	struct sdirs *sdirs, const char *incexc,
	int *resume, struct conf **cconfs);

#endif
