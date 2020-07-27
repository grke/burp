#ifndef _ASFD_H
#define _ASFD_H

#include "burp.h"
#include "cmd.h"
#include "ssl.h"
#include "cntr.h"

// Return values for simple_loop().
enum asl_ret
{
	ASL_END_ERROR=-1,
	ASL_CONTINUE=0,
	ASL_END_OK=1,
	ASL_END_OK_RETURN_1=2
};

enum asfd_streamtype
{
	ASFD_STREAM_STANDARD=0,
	ASFD_STREAM_LINEBUF,
	ASFD_STREAM_NCURSES_STDIN
};

enum asfd_fdtype
{
	ASFD_FD_UNSET=0,
	ASFD_FD_SERVER_LISTEN_MAIN,
	ASFD_FD_SERVER_LISTEN_STATUS,
	ASFD_FD_SERVER_PIPE_READ,
	ASFD_FD_SERVER_PIPE_WRITE,
};

enum append_ret
{
	APPEND_ERROR=-1,
	APPEND_OK=0,
	APPEND_BLOCKED=1
};

// Async file descriptor. Can add these to a struct async.
struct asfd
{
	int fd;
	SSL *ssl;
	struct async *as;
	char *desc;
	enum asfd_streamtype streamtype;
	char *listen;
	const char *peer_addr;

	int network_timeout;
	int max_network_timeout;

	float ratelimit;
	time_t rlstart;
	int rlsleeptime;
	uint64_t rlbytes;

	struct iobuf *rbuf;

	int attempt_reads;

	int doread;
	char *readbuf;
	size_t readbuflen;
	int read_blocked_on_write;
	size_t bufmaxsize;

	int dowrite;
	char *writebuf;
	size_t writebuflen;
	int write_blocked_on_read;

	int errors;

	struct asfd *next;

	// Stuff for the champ chooser server.
	struct incoming *in;
	struct blist *blist;
	int blkcnt;
	uint64_t wrap_up;
	uint8_t want_to_remove;

	// For the champ chooser server main socket.
	uint8_t listening_for_new_clients;
	uint8_t new_client;

	// For the main server process.
	pid_t pid;
	enum asfd_fdtype fdtype;
	enum cntr_status cntr_status;
	char *client;

	// Counters
	uint64_t sent;
	uint64_t rcvd;

	// Function pointers.
	int (*parse_readbuf)(struct asfd *);
	int (*parse_readbuf_specific)(struct asfd *);
	enum append_ret
		(*append_all_to_write_buffer)(struct asfd *, struct iobuf *);
	int (*set_bulk_packets)(struct asfd *);
	void (*set_timeout)(struct asfd *, int max_network_timeout);
	int (*do_read)(struct asfd *);
	int (*do_write)(struct asfd *);
	int (*read)(struct asfd *);
	int (*simple_loop)(struct asfd *, struct conf **, void *,
		const char *, enum asl_ret callback(struct asfd *,
			struct conf **, void *));
	int (*write)(struct asfd *, struct iobuf *);
	int (*write_str)(struct asfd *, enum cmd, const char *);

#ifdef UTEST
	// To assist mocking functions in unit tests.
	void *data1;
	void *data2;
#endif
};

extern struct asfd *asfd_alloc(void);
extern void asfd_close(struct asfd *asfd); // Maybe should be in the struct.
extern void asfd_free(struct asfd **asfd);

extern struct asfd *setup_asfd(struct async *as,
	const char *desc, int *fd, const char *listen);
extern struct asfd *setup_asfd_ssl(struct async *as,
	const char *desc, int *fd, SSL *ssl);
extern struct asfd *setup_asfd_linebuf_read(struct async *as,
	const char *desc, int *fd);
extern struct asfd *setup_asfd_linebuf_write(struct async *as,
	const char *desc, int *fd);
extern struct asfd *setup_asfd_stdin(struct async *as);
extern struct asfd *setup_asfd_stdout(struct async *as);
extern struct asfd *setup_asfd_ncurses_stdin(struct async *as);

extern int asfd_flush_asio(struct asfd *asfd);
extern int asfd_write_wrapper(struct asfd *asfd, struct iobuf *wbuf);
extern int asfd_write_wrapper_str(struct asfd *asfd,
	enum cmd wcmd, const char *wsrc);

extern int asfd_read_expect(struct asfd *asfd,
	enum cmd cmd, const char *expect);

#ifdef UTEST
extern int asfd_simple_loop(struct asfd *asfd,
	struct conf **confs, void *param, const char *caller,
	enum asl_ret callback(struct asfd *asfd,
		struct conf **confs, void *param));
#endif

#endif
