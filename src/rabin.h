#ifndef __RABIN_H
#define __RABIN_H

#include <stdio.h>
#include "bfile.h"
#include "rconf.h"

extern int blks_generate(struct rconf *rconf, BFILE *bfd, FILE *fp);

#endif
