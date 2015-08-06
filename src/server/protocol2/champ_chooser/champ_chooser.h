#ifndef _CHAMP_CHOOSER_H
#define _CHAMP_CHOOSER_H

extern struct scores *champ_chooser_init(const char *datadir);

extern int deduplicate(struct asfd *asfd, const char *directory,
	struct scores *scores);

#endif
