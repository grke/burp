#ifndef __CHAMP_CHOOSER_H
#define __CHAMP_CHOOSER_H

extern int champ_chooser_init(const char *sparse, struct conf **confs);

extern int deduplicate(struct asfd *asfd, struct conf **confs);
extern int is_hook(uint64_t fingerprint);

#endif
