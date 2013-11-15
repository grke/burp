#ifndef _ASYNCIO_ROUTINES_H
#define _ASYNCIO_ROUTINES_H

#define ASYNC_BUF_LEN	16000
#define ZCHUNK		ASYNC_BUF_LEN

#include <zlib.h>
#include "cmd.h"
#include "ssl.h"

extern int status_wfd; // for the child to send information to the parent.
extern int status_rfd; // for the child to read information from the parent.

extern size_t writebuflen;

extern int async_init(int afd, SSL *assl, struct config *conf, int estimate);
extern void async_free(void);

extern int async_get_fd(void);

// This one can return without completing the read or write, so check
// rbuf->buf and/or wbuf->len.
extern int async_rw(struct iobuf *rbuf, struct iobuf *wbuf);

extern int async_read_quick(struct iobuf *rbuf);

extern int async_read(struct iobuf *rbuf);
extern int async_write(struct iobuf *wbuf);

extern int async_write_str(char wcmd, const char *wsrc);
extern int async_read_expect(char cmd, const char *expect);

extern void log_and_send(const char *msg);
extern void log_and_send_oom(const char *function);

// for debug purposes
extern void settimers(int sec, int usec);

// should be in src/lib/log.c
int logw(struct cntr *cntr, const char *fmt, ...);

extern int set_bulk_packets(void);

#endif
