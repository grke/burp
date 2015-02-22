#ifndef _CHAMP_CLIENT_H
#define _CHAMP_CLIENT_H

#include "include.h"
#include "../../../server/sdirs.h"

extern struct asfd *champ_chooser_connect(struct async *as,
        struct sdirs *sdirs, struct conf **confs);

#endif
