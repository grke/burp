#ifndef __RABIN_H
#define __RABIN_H

#include <stdio.h>

#include "rabin_win.h"
#include "rconf.h"
#include "sbuf.h"

extern int blks_generate(struct blkgrp **bnew, struct rconf *rconf, struct sbuf *sb, struct win *win);

#endif
