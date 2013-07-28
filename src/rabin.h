#ifndef __RABIN_H
#define __RABIN_H

#include <stdio.h>

#include "rabin_win.h"
#include "rconf.h"
#include "sbuf.h"

extern int blks_generate(struct rconf *rconf, struct sbuf *sb, struct win *win, uint64_t *bindex);

#endif
