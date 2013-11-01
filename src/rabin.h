#ifndef __RABIN_H
#define __RABIN_H

#include <stdio.h>

#include "rabin_win.h"
#include "conf.h"
#include "sbuf.h"

extern int blks_generate_init(struct config *conf);
extern int blks_generate(struct config *conf, struct sbuf *sb, struct blist *blist, struct win *win);

#endif
