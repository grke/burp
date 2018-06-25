#ifndef _RUBBLE_H
#define _RUBBLE_H

// Return 0 if there is no rubble.
extern int check_for_rubble(struct sdirs *sdirs);

// Return 1 if the backup is now finalising.
extern int check_for_rubble_and_clean(struct async *as,
	struct sdirs *sdirs, const char *incexc,
	int *resume, struct conf **cconfs);

#endif
