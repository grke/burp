#ifndef _ZLIBIO_H
#define _ZLIBIO_H

extern int zlib_inflate(struct asfd *asfd, const char *source,
	const char *dest, struct cntr *cntr);

#endif
