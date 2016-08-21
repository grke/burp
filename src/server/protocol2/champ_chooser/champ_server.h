#ifndef _CHAMP_SERVER_H
#define _CHAMP_SERVER_H

#include "asfd.h"

#include "server/sdirs.h"
#include "server/protocol2/champ_chooser/scores.h"

extern int champ_chooser_server(struct sdirs *sdirs, struct conf **confs,
	int resume);
extern int champ_chooser_server_standalone(struct conf **globalcs);

#ifdef UTEST
extern int champ_server_deal_with_rbuf_sig(struct asfd *asfd,
	const char *directory, struct scores *scores);
#endif

#endif
