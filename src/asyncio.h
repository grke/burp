#ifndef _ASYNCIO_ROUTINES_H
#define _ASYNCIO_ROUTINES_H

#define ASYNC_BUF_LEN	16000
#define ZCHUNK		ASYNC_BUF_LEN

#include <zlib.h>
#include "cmd.h"
#include "ssl.h"

// Return values for simple_loop().
enum asl_ret
{
	ASL_END_ERROR=-1,
	ASL_CONTINUE=0,
	ASL_END_OK=1,
	ASL_END_OK_RETURN_1=2
};

struct asfd
{
	int fd;
	SSL *ssl;

	int network_timeout;
	int max_network_timeout;

	float ratelimit;
	time_t rlstart;
	int rlsleeptime;
	unsigned long long rlbytes;

	// Maybe turn these into iobufs.
	char *readbuf;
	size_t readbuflen;
	int read_blocked_on_write;

	char *writebuf;
	size_t writebuflen;
	int write_blocked_on_read;

	// Function pointers.
	int (*init)(struct asfd *, int, SSL *, struct conf *);
	int (*append_all_to_write_buffer)(struct asfd *, struct iobuf *);
	int (*set_bulk_packets)(struct asfd *);
};

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
	int (*rw)(struct async *, struct iobuf *, struct iobuf *);
	int (*read)(struct async *, struct iobuf *);
	int (*write)(struct async *, struct iobuf *);
	int (*read_quick)(struct async *, struct iobuf *);
	int (*write_strn)(struct async *, char, const char *, size_t);
	int (*write_str)(struct async *, char, const char *);
	int (*read_expect)(struct async *, char, const char *);
	int (*simple_loop)(struct async *, struct conf *, void *,
		const char *, enum asl_ret callback(struct async *,
			  struct iobuf *, struct conf *, void *));
	void (*settimers)(struct async *, int, int); // For debug purposes.
};

extern struct async *async_alloc(void);
extern void async_free(struct async **as);

#endif
