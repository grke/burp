#ifndef _FIND_LOGIC_H
#define _FIND_LOGIC_H

#include "find.h"

extern void free_logic_cache(void);
extern int is_logic_excluded(struct conf **confs, struct FF_PKT *ff);
extern int is_logic_included(struct conf **confs, struct FF_PKT *ff);

#endif
