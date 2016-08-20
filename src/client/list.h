#ifndef _LIST_CLIENT_H
#define _LIST_CLIENT_H

#include "action.h"
#include "asfd.h"
#include "conf.h"

extern int do_list_client(struct asfd *asfd,
	enum action act, struct conf **confs);

#endif
