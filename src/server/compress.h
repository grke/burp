#ifndef _COMPRESS_H
#define _COMPRESS_H

extern char *comp_level(struct conf **confs);
extern int compress_file(const char *current, const char *file,
	struct conf **cconf);
extern int compress_filename(const char *d, const char *file,
	const char *zfile, struct conf **cconf);

#endif
