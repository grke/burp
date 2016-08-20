#ifndef _MANIOS_H
#define _MANIOS_H

#include "server/manio.h"

typedef struct manios
{
	struct manio *current;
	struct manio *phase1;
	struct manio *changed;
	struct manio *unchanged;
} manios;

extern struct manios *manios_open_phase2(struct sdirs *sdirs,
	man_off_t *p1pos, enum protocol p);
extern int manios_close(struct manios **manios);

#endif
