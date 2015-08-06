#ifndef _COMPRESS_H
#define _COMPRESS_H

extern char *comp_level(int compression);
extern int compress_file(const char *current, const char *file,
	int compression);
extern int compress_filename(const char *d, const char *file,
	const char *zfile, int compression);

#endif
