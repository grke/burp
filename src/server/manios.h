#ifndef _MANIOS_H
#define _MANIOS_H

#include "manio.h"

struct manios
{
	struct manio *current;
	struct manio *phase1;
	struct manio *changed;
	struct manio *unchanged;
	struct manio *counters_d; // data entries
	struct manio *counters_n; // non-data entries
};

extern struct manios *manios_open_phase2(struct sdirs *sdirs,
	man_off_t *pos_phase1,
	man_off_t *pos_current);
extern int manios_close(struct manios **manios);

#endif
