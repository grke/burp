#ifndef _ASYNC_H
#define _ASYNC_H

#define ASYNC_BUF_LEN	16000
#define ZCHUNK		ASYNC_BUF_LEN

struct async
{
	// FIX THIS: Make asfd into a list, so that multiple fds can be
	// written/read.
	struct asfd *asfd;

	int doing_estimate;

	int setsec;
	int setusec;

	// Let us try using function pointers.
	int (*init)(struct async *, int, SSL *, struct conf *, int);
	// This one can return without completing the read or write, so check
	// rbuf->buf and/or wbuf->len.
	int (*rw)(struct async *, struct iobuf *);
	int (*write)(struct async *, struct iobuf *);
	int (*read_quick)(struct async *);
	int (*write_strn)(struct async *, char, const char *, size_t);
	int (*write_str)(struct async *, char, const char *);
	void (*settimers)(struct async *, int, int); // For debug purposes.
};

extern struct async *async_alloc(void);
extern void async_free(struct async **as);

#endif
