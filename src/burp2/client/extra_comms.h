#ifndef _EXTRA_COMMS_CLIENT_H
#define _EXTRA_COMMS_CLIENT_H

extern int extra_comms(struct asfd *asfd, struct conf *conf,
	enum action *action, char **incexc, long *name_max);

#endif
