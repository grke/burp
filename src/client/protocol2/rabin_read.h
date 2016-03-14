#ifndef _RABIN_READ_H
#define _RABIN_READ_H

extern int rabin_open_file(struct sbuf *sb,
	struct asfd *asfd, struct cntr *cntr, struct conf **confs);
extern int rabin_close_file(struct sbuf *sb, struct asfd *asfd);
extern ssize_t rabin_read(struct sbuf *sb, char *buf, size_t bufsize);

#endif
