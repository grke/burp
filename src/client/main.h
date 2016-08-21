#ifndef _CLIENT_MAIN_H
#define _CLIENT_MAIN_H

#include "action.h"
#include "conf.h"

extern int client(struct conf **confs, enum action act, int vss_restore);

#endif
