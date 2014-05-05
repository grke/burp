#ifndef _CHAMP_SERVER_H
#define _CHAMP_SERVER_H

extern int champ_chooser_server(struct sdirs *sdirs, struct conf *conf);
extern int champ_chooser_server_standalone(struct conf *conf,
	const char *sclient);

#endif
