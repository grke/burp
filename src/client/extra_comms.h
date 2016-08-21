#ifndef _EXTRA_COMMS_CLIENT_H
#define _EXTRA_COMMS_CLIENT_H

#include "action.h"
#include "async.h"
#include "conf.h"

extern int extra_client_comms(struct async *as, struct conf **confs,
	enum action *action, char **incexc);

#endif
