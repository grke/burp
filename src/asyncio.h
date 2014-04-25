#ifndef _ASYNCIO_ROUTINES_H
#define _ASYNCIO_ROUTINES_H

#define ASYNC_BUF_LEN	16000
#define ZCHUNK		ASYNC_BUF_LEN

#include <zlib.h>
#include "cmd.h"
#include "ssl.h"

extern int status_wfd; // for the child to send information to the parent.
extern int status_rfd; // for the child to read information from the parent.

struct async
{
	int fd;
	SSL *ssl;
	int network_timeout;
	int max_network_timeout;
	int doing_estimate;

	char *readbuf;
	size_t readbuflen;
	int read_blocked_on_write;

	// Maybe turn these into iobufs.
	char *writebuf;
	size_t writebuflen;
	int write_blocked_on_read;

	float ratelimit;
	time_t rlstart;
	int rlsleeptime;
	unsigned long long rlbytes;
};

extern struct async *async_alloc(void);
extern int async_init(struct async *as,
	int afd, SSL *assl, struct conf *conf, int estimate);
extern void async_free(struct async **as);

// This one can return without completing the read or write, so check
// rbuf->buf and/or wbuf->len.
extern int async_rw(struct async *as, struct iobuf *rbuf, struct iobuf *wbuf);

extern int async_read_quick(struct async *as, struct iobuf *rbuf);

extern int async_read(struct async *as, struct iobuf *rbuf);
extern int async_write(struct async *as, struct iobuf *wbuf);

extern int async_write_strn(struct async *as,
	char wcmd, const char *wsrc, size_t len);
extern int async_write_str(struct async *as,
	char wcmd, const char *wsrc);
extern int async_read_expect(struct async *as,
	char cmd, const char *expect);

extern int async_append_all_to_write_buffer(struct async *as,
	struct iobuf *wbuf);

enum asl_ret
{
	ASL_END_ERROR=-1,
	ASL_CONTINUE=0,
	ASL_END_OK=1,
	ASL_END_OK_RETURN_1=2
};

extern int async_simple_loop(struct async *as, struct conf *conf, void *param,
  const char *caller,
  enum asl_ret callback(struct async *as,
	struct iobuf *rbuf, struct conf *conf, void *param));

extern void log_and_send(struct async *as, const char *msg);
extern void log_and_send_oom(struct async *as, const char *function);

// for debug purposes
extern void settimers(int sec, int usec);

// should be in src/lib/log.c
int logw(struct async *as, struct conf *conf, const char *fmt, ...);

extern int async_set_bulk_packets(struct async *as);

#endif
