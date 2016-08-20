#ifndef _EXTRA_COMMS_CLIENT_H
#define _EXTRA_COMMS_CLIENT_H

extern int extra_client_comms(struct async *as, struct conf **confs,
	enum action *action, char **incexc);

#endif
