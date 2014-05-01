#ifndef __CLIFD_H
#define __CLIFD_H

typedef struct clifd clifd_t;

struct clifd
{
	int fd;
	char *cname;
	struct incoming *in;
	struct blist *blist;
	int blkcnt;
	uint64_t wrap_up;
	uint64_t consecutive_got;

	char *readbuf;
	size_t readbuflen;
	struct iobuf *rbuf;

	char *writebuf;
	size_t writebuflen;
	struct iobuf *wbuf;

	struct clifd *next;
};

extern int clifd_alloc_buf(char **buf, size_t *buflen, size_t bufmaxlen);
extern void clifd_free(struct clifd *c);
extern void clifd_remove(struct clifd **clifds, struct clifd *c);
extern void clifd_truncate_buf(char **buf, size_t *buflen);

#endif
