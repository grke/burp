#ifndef _EXTRA_COMMS_CLIENT_H
#define _EXTRA_COMMS_CLIENT_H

extern int extra_comms_client(struct async *as, struct conf **confs,
	enum action *action, struct strlist *failover, char **incexc);

#endif
