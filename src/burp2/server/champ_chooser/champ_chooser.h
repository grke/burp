#ifndef __CHAMP_CHOOSER_H
#define __CHAMP_CHOOSER_H

extern int champ_chooser_init(const char *sparse, struct conf *conf);

extern int deduplicate(struct asfd *asfd, struct conf *conf);
extern int is_hook(const char *str);

#endif
