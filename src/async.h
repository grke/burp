#ifndef _ASYNC_H
#define _ASYNC_H

#define ASYNC_BUF_LEN	16000
#define ZCHUNK		ASYNC_BUF_LEN

struct async
{
	struct asfd *asfd;

	int doing_estimate;

	int setsec;
	int setusec;

	// Let us try using function pointers.
	int (*init)(struct async *, int);

	// These two can return without completing the read or write, so check
	// rbuf->buf and/or wbuf->len.
	int (*read_write)(struct async *);
	int (*write)(struct async *);

	int (*read_quick)(struct async *);
	void (*add_asfd)(struct async *, struct asfd *);
	void (*settimers)(struct async *, int, int); // For debug purposes.
};

extern struct async *async_alloc(void);
extern void async_free(struct async **as);

#endif
