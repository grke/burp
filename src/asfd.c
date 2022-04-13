#include "burp.h"
#include "alloc.h"
#include "asfd.h"
#include "async.h"
#include "cmd.h"
#include "fsops.h"
#include "handy.h"
#include "iobuf.h"
#include "log.h"

// For IPTOS / IPTOS_THROUGHPUT.
#ifdef HAVE_WIN32
#include <ws2tcpip.h>
#else
#include <netinet/ip.h>
#endif

#ifdef HAVE_NCURSES_H
#include <ncurses.h>
#elif HAVE_NCURSES_NCURSES_H
#include <ncurses/ncurses.h>
#endif

static void truncate_readbuf(struct asfd *asfd)
{
	asfd->readbuf[0]='\0';
	asfd->readbuflen=0;
}

static int asfd_alloc_buf(struct asfd *asfd, char **buf)
{
	if(!*buf && !(*buf=(char *)calloc_w(1, asfd->bufmaxsize, __func__)))
		return -1;
	return 0;
}

static int extract_buf(struct asfd *asfd,
	size_t len, size_t offset)
{
	if(offset+len>=asfd->bufmaxsize)
	{
		logp("%s: offset(%lu)+len(%lu)>=asfd->bufmaxsize(%lu) in %s!",
			asfd->desc,
			(unsigned long)offset,
			(unsigned long)len,
			(unsigned long)asfd->bufmaxsize,
			__func__);
		return -1;
	}

	if(!(asfd->rbuf->buf=(char *)malloc_w(len+1, __func__)))
		return -1;
	if(!(memcpy(asfd->rbuf->buf, asfd->readbuf+offset, len)))
	{
		logp("%s: memcpy failed in %s\n", asfd->desc, __func__);
		return -1;
	}
	asfd->rbuf->buf[len]='\0';
	if(!(memmove(asfd->readbuf,
		asfd->readbuf+len+offset, asfd->readbuflen-len-offset)))
	{
		logp("%s: memmove failed in %s\n", asfd->desc, __func__);
		return -1;
	}
	asfd->readbuflen-=len+offset;
	asfd->rbuf->len=len;
	return 0;
}

#ifdef HAVE_NCURSES
static int parse_readbuf_ncurses(struct asfd *asfd)
{
	if(!asfd->readbuflen) return 0;
	// This is reading ints, and will be cast back to an int when it comes
	// to be processed later.
	if(extract_buf(asfd, asfd->readbuflen, 0)) return -1;
	return 0;
}
#endif

static int parse_readbuf_line_buf(struct asfd *asfd)
{
	static char *cp=NULL;
	static char *dp=NULL;
	static size_t len=0;
	if(!cp)
	{
		// Only start from the beginning if we previously got something
		// to extract.
		cp=asfd->readbuf;
		len=0;
	}
	for(; len<asfd->readbuflen; cp++, len++)
	{
		if(*cp!='\n') continue;
		len++;
		if(extract_buf(asfd, len, 0)) return -1;
		// Strip trailing white space, like '\r\n'.
		dp=asfd->rbuf->buf;
		for(cp=&(dp[len-1]); cp>=dp && isspace(*cp); cp--, len--)
			*cp='\0';
		asfd->rbuf->len=len;
		break;
	}
	cp=NULL;
	return 0;
}

static int parse_readbuf_standard(struct asfd *asfd)
{
	unsigned int s=0;
	char command;
	if(asfd->readbuflen<5) return 0;
	if((sscanf(asfd->readbuf, "%c%04X", &command, &s))!=2)
	{
		logp("%s: sscanf of '%s' failed in %s\n",
			asfd->desc, asfd->readbuf, __func__);
		return -1;
	}
	if(s>=asfd->bufmaxsize)
	{
		logp("%s: given buffer length '%d', which is too big!\n",
			asfd->desc, s);
		return -1;
	}
	if(asfd->readbuflen>=s+5)
	{
		asfd->rbuf->cmd=(enum cmd)command;
		if(extract_buf(asfd, (size_t)s, 5))
			return -1;
	}
	return 0;
}

static int asfd_parse_readbuf(struct asfd *asfd)
{
	if(asfd->rbuf->buf) return 0;

	if(asfd->parse_readbuf_specific(asfd))
	{
		truncate_readbuf(asfd);
		return -1;
	}

	return 0;
}

#ifdef HAVE_NCURSES
static int asfd_do_read_ncurses(struct asfd *asfd)
{
	static int i;
	i=getch();
	asfd->readbuflen=sizeof(int);
	memcpy(asfd->readbuf, &i, asfd->readbuflen);
	return 0;
}

static int asfd_do_write_ncurses(__attribute__ ((unused)) struct asfd *asfd)
{
	logp("This function should not have been called: %s\n", __func__);
	return -1;
}
#endif

static int asfd_do_read(struct asfd *asfd)
{
	ssize_t r;
	r=read(asfd->fd,
	  asfd->readbuf+asfd->readbuflen, asfd->bufmaxsize-asfd->readbuflen);
	if(r<0)
	{
		if(errno==EAGAIN || errno==EINTR)
			return 0;
		logp("%s: read problem on fd %d: %s\n",
			asfd->desc, asfd->fd, strerror(errno));
		goto error;
	}
	else if(!r)
	{
		// End of data.
		logp("%s: end of data\n", asfd->desc);
		goto error;
	}
	asfd->readbuflen+=r;
	asfd->rcvd+=r;
	return 0;
error:
	truncate_readbuf(asfd);
	return -1;
}

static void peer_msg(void)
{
	logp("This is probably caused by the peer exiting.\n");
	logp("Please check the peer's logs.\n");
}

static int asfd_do_read_ssl(struct asfd *asfd)
{
	int e;
	ssize_t r;

	asfd->read_blocked_on_write=0;

	ERR_clear_error();
	r=SSL_read(
		asfd->ssl,
		asfd->readbuf+asfd->readbuflen,
		asfd->bufmaxsize-asfd->readbuflen
	);

	switch((e=SSL_get_error(asfd->ssl, r)))
	{
		case SSL_ERROR_NONE:
			asfd->readbuflen+=r;
			asfd->rcvd+=r;
			break;
		case SSL_ERROR_ZERO_RETURN:
			// End of data.
			logp("%s: Peer closed SSL session\n", asfd->desc);
			SSL_shutdown(asfd->ssl);
			goto error;
		case SSL_ERROR_WANT_READ:
			break;
		case SSL_ERROR_WANT_WRITE:
			asfd->read_blocked_on_write=1;
			break;
		case SSL_ERROR_SYSCALL:
			if(errno==EAGAIN || errno==EINTR)
				break;
			logp("%s: Got network read error\n",
				asfd->desc);
			// Fall through to read problem
		default:
			asfd->errors++;
			logp_ssl_err(
				"%s: network read problem in %s: %d - %d=%s\n",
				asfd->desc, __func__,
				e, errno, strerror(errno));
			peer_msg();
			goto error;
	}
	return 0;
error:
	truncate_readbuf(asfd);
	return -1;
}

// Return 0 for OK to write, non-zero for not OK to write.
static int check_ratelimit(struct asfd *asfd)
{
	float f;
	time_t diff;
	if(!asfd->rlstart) asfd->rlstart=time(NULL);
	if((diff=asfd->as->now-asfd->rlstart)<0)
	{
		// It is possible that the clock changed. Reset ourselves.
		asfd->as->now=asfd->rlstart;
		asfd->rlbytes=0;
		logp("Looks like the clock went back in time since starting. "
			"Resetting ratelimit\n");
		return 0;
	}
	if(!diff) return 0; // Need to get started somehow.
	f=(asfd->rlbytes)/diff; // Bytes per second.

	if(f>=asfd->ratelimit)
	{
#ifdef HAVE_WIN32
		// Windows Sleep is milliseconds, usleep is microseconds.
		// Do some conversion.
		Sleep(asfd->rlsleeptime/1000);
#else
		usleep(asfd->rlsleeptime);
#endif
		// If sleeping, increase the sleep time.
		if((asfd->rlsleeptime*=2)>=500000) asfd->rlsleeptime=500000;
		return 1;
	}
	// If not sleeping, decrease the sleep time.
	if((asfd->rlsleeptime/=2)<=9999) asfd->rlsleeptime=10000;
	return 0;
}

static int asfd_do_write(struct asfd *asfd)
{
	ssize_t w;
	if(asfd->ratelimit && check_ratelimit(asfd)) return 0;

	w=write(asfd->fd, asfd->writebuf, asfd->writebuflen);
	if(w<0)
	{
		if(errno==EAGAIN || errno==EINTR)
			return 0;
		logp("%s: Got error in %s, (%d=%s)\n", __func__,
			asfd->desc, errno, strerror(errno));
		asfd->errors++;
		return -1;
	}
	else if(!w)
	{
		logp("%s: Wrote nothing in %s\n", asfd->desc, __func__);
		asfd->errors++;
		return -1;
	}
	if(asfd->ratelimit) asfd->rlbytes+=w;
	asfd->sent+=w;
/*
{
char buf[100000]="";
snprintf(buf, w+1, "%s", asfd->writebuf);
printf("wrote %d: %s\n", w, buf);
}
*/

	memmove(asfd->writebuf, asfd->writebuf+w, asfd->writebuflen-w);
	asfd->writebuflen-=w;
	return 0;
}

static int asfd_do_write_ssl(struct asfd *asfd)
{
	int e;
	ssize_t w;

	asfd->write_blocked_on_read=0;

	if(asfd->ratelimit && check_ratelimit(asfd)) return 0;
	ERR_clear_error();
	w=SSL_write(asfd->ssl, asfd->writebuf, asfd->writebuflen);

	switch((e=SSL_get_error(asfd->ssl, w)))
	{
		case SSL_ERROR_NONE:
/*
{
char buf[100000]="";
snprintf(buf, w+1, "%s", asfd->writebuf);
printf("wrote %d: %s\n", w, buf);
}
*/
			if(asfd->ratelimit) asfd->rlbytes+=w;
			memmove(asfd->writebuf,
				asfd->writebuf+w, asfd->writebuflen-w);
			asfd->writebuflen-=w;
			asfd->sent+=w;
			break;
		case SSL_ERROR_WANT_WRITE:
			break;
		case SSL_ERROR_WANT_READ:
			asfd->write_blocked_on_read=1;
			break;
		case SSL_ERROR_SYSCALL:
			if(errno==EAGAIN || errno==EINTR)
				break;
			logp("%s: Got network write error\n",
				asfd->desc);
			// Fall through to write problem
		default:
			asfd->errors++;
			logp_ssl_err(
				"%s: network write problem in %s: %d - %d=%s\n",
				asfd->desc, __func__,
				e, errno, strerror(errno));
			peer_msg();
			return -1;
	}
	return 0;
}

static int append_to_write_buffer(struct asfd *asfd,
	const char *buf, size_t len)
{
	memcpy(asfd->writebuf+asfd->writebuflen, buf, len);
	asfd->writebuflen+=len;
	asfd->writebuf[asfd->writebuflen]='\0';
	return 0;
}

static enum append_ret asfd_append_all_to_write_buffer(struct asfd *asfd,
	struct iobuf *wbuf)
{
	switch(asfd->streamtype)
	{
		case ASFD_STREAM_STANDARD:
		{
			size_t sblen=0;
			char sbuf[10]="";
			if(asfd->writebuflen+6+(wbuf->len)>=asfd->bufmaxsize-1)
				return APPEND_BLOCKED;

			snprintf(sbuf, sizeof(sbuf), "%c%04X",
				wbuf->cmd, (unsigned int)wbuf->len);
			sblen=strlen(sbuf);
			append_to_write_buffer(asfd, sbuf, sblen);
			break;
		}
		case ASFD_STREAM_LINEBUF:
			if(asfd->writebuflen+wbuf->len>=asfd->bufmaxsize-1)
				return APPEND_BLOCKED;
			break;
		case ASFD_STREAM_NCURSES_STDIN:
		default:
			logp("%s: unknown asfd stream type in %s: %d\n",
				asfd->desc, __func__, asfd->streamtype);
			return APPEND_ERROR;
	}
	append_to_write_buffer(asfd, wbuf->buf, wbuf->len);
//printf("append %s\n", iobuf_to_printable(wbuf));
	wbuf->len=0;
	return APPEND_OK;
}

#ifdef IPTOS_THROUGHPUT
static int asfd_connection_af(struct asfd *asfd)
{
	struct sockaddr_storage s;
	socklen_t slen = sizeof(s);

	memset(&s, 0, sizeof(s));
	if(getsockname(asfd->fd, (struct sockaddr *)&s, &slen)<0)
		return 0;
	return s.ss_family;
}
#endif

static int asfd_set_bulk_packets(struct asfd *asfd)
{
#ifdef IPTOS_THROUGHPUT
	int opt=IPTOS_THROUGHPUT;
	if(asfd->fd<0) return -1;

	switch(asfd_connection_af(asfd))
	{
		case AF_INET:
			if(setsockopt(asfd->fd, IPPROTO_IP, IP_TOS,
				(char *)&opt, sizeof(opt))>=0)
					break;
			logp("%s: error: set IPTOS throughput: %s\n",
				asfd->desc, strerror(errno));
			return -1;
		case AF_INET6:
			if(setsockopt(asfd->fd, IPPROTO_IPV6, IPV6_TCLASS,
				(char *)&opt, sizeof(opt))>=0)
					break;
			logp("%s: error: set IPV6_TCLASS throughput: %s\n",
				asfd->desc, strerror(errno));
			return -1;
	}
#endif
	return 0;
}

static int asfd_read(struct asfd *asfd)
{
	if(asfd->as->doing_estimate) return 0;
	while(!asfd->rbuf->buf)
	{
		if(asfd->errors)
			return -1;
		if(asfd->as->read_write(asfd->as))
			return -1;
	}
	return 0;
}

int asfd_read_expect(struct asfd *asfd, enum cmd cmd, const char *expect)
{
	int ret=0;
	if(asfd->read(asfd)) return -1;
	if(asfd->rbuf->cmd!=cmd || strcmp(asfd->rbuf->buf, expect))
	{
		logp("%s: expected '%c:%s', got '%s'\n",
			asfd->desc, cmd, expect,
			iobuf_to_printable(asfd->rbuf));
		ret=-1;
	}
	iobuf_free_content(asfd->rbuf);
	return ret;
}

static int asfd_write(struct asfd *asfd, struct iobuf *wbuf)
{
	if(asfd->as->doing_estimate) return 0;
	while(wbuf->len)
	{
		if(asfd->errors)
			return -1;
		if(asfd->append_all_to_write_buffer(asfd, wbuf)==APPEND_ERROR)
			return -1;
		if(asfd->as->write(asfd->as)) return -1;
	}
	return 0;
}

static int asfd_write_str(struct asfd *asfd, enum cmd wcmd, const char *wsrc)
{
	struct iobuf wbuf;
	wbuf.cmd=wcmd;
	wbuf.buf=(char *)wsrc;
	wbuf.len=strlen(wsrc);
	return asfd->write(asfd, &wbuf);
}

#ifndef UTEST
static
#endif
int asfd_simple_loop(struct asfd *asfd,
	struct conf **confs, void *param, const char *caller,
  enum asl_ret callback(struct asfd *asfd, struct conf **confs, void *param))
{
	struct iobuf *rbuf=asfd->rbuf;
	while(1)
	{
		iobuf_free_content(rbuf);
		if(asfd->read(asfd)) goto error;
		if(!rbuf->buf) continue;
		if(rbuf->cmd!=CMD_GEN)
		{
			if(rbuf->cmd==CMD_WARNING
			  || rbuf->cmd==CMD_MESSAGE)
			{
				struct cntr *cntr=NULL;
				if(confs) cntr=get_cntr(confs);
				log_recvd(rbuf, cntr, 0);
			}
			else if(rbuf->cmd==CMD_INTERRUPT)
			{
				// Ignore - client wanted to interrupt a file.
			}
			else
			{
				logp("%s: unexpected command in %s(), called from %s(): %s\n", asfd->desc, __func__, caller, iobuf_to_printable(rbuf));
				goto error;
			}
			continue;
		}
		switch(callback(asfd, confs, param))
		{
			case ASL_CONTINUE: break;
			case ASL_END_OK:
				iobuf_free_content(rbuf);
				return 0;
			case ASL_END_OK_RETURN_1:
				iobuf_free_content(rbuf);
				return 1;
			case ASL_END_ERROR:
			default:
				goto error;
		}
	}
error:
	iobuf_free_content(rbuf);
	return -1;
}

static void asfd_set_timeout(struct asfd *asfd, int max_network_timeout)
{
	asfd->max_network_timeout=max_network_timeout;
	asfd->network_timeout=asfd->max_network_timeout;
}

static char *get_asfd_desc(const char *desc, int fd)
{
	char r[256]="";
	snprintf(r, sizeof(r), "%s %d", desc, fd);
	return strdup_w(r, __func__);
}

static int asfd_init(struct asfd *asfd, const char *desc,
	struct async *as, int afd, const char *listen,
	SSL *assl, enum asfd_streamtype streamtype)
{
	asfd->as=as;
	asfd->fd=afd;
	asfd->ssl=assl;
	asfd->streamtype=streamtype;
	asfd->rlsleeptime=10000;
	asfd->pid=-1;
	asfd->attempt_reads=1;
	asfd->bufmaxsize=(ASYNC_BUF_LEN*2)+32;
#ifdef HAVE_WIN32
	// Windows craps out if you try to read stdin into a buffer that is
	// too big!
	if(asfd->fd==fileno(stdin))
		asfd->bufmaxsize=4096;
#endif

	asfd->parse_readbuf=asfd_parse_readbuf;
	asfd->append_all_to_write_buffer=asfd_append_all_to_write_buffer;
	asfd->set_bulk_packets=asfd_set_bulk_packets;
	asfd->set_timeout=asfd_set_timeout;
	if(asfd->ssl)
	{
		asfd->do_read=asfd_do_read_ssl;
		asfd->do_write=asfd_do_write_ssl;
	}
	else
	{
		asfd->do_read=asfd_do_read;
		asfd->do_write=asfd_do_write;
#ifdef HAVE_NCURSES
		if(asfd->streamtype==ASFD_STREAM_NCURSES_STDIN)
		{
			asfd->do_read=asfd_do_read_ncurses;
			asfd->do_write=asfd_do_write_ncurses;
		}
#endif
	}
	asfd->read=asfd_read;
	asfd->simple_loop=asfd_simple_loop;
	asfd->write=asfd_write;
	asfd->write_str=asfd_write_str;

	switch(asfd->streamtype)
	{
		case ASFD_STREAM_STANDARD:
			asfd->parse_readbuf_specific=parse_readbuf_standard;
			break;
		case ASFD_STREAM_LINEBUF:
			asfd->parse_readbuf_specific=parse_readbuf_line_buf;
			break;
#ifdef HAVE_NCURSES
		case ASFD_STREAM_NCURSES_STDIN:
			asfd->parse_readbuf_specific=parse_readbuf_ncurses;
			break;
#endif
		default:
			logp("%s: unknown asfd stream type in %s: %d\n",
				desc, __func__, asfd->streamtype);
			return -1;
	}

	if(!(asfd->rbuf=iobuf_alloc())
	  || asfd_alloc_buf(asfd, &asfd->readbuf)
	  || asfd_alloc_buf(asfd, &asfd->writebuf)
	  || !(asfd->desc=get_asfd_desc(desc, asfd->fd))
	  || !(asfd->listen=strdup_w(listen, __func__)))
		return -1;
	return 0;
}

struct asfd *asfd_alloc(void)
{
	struct asfd *asfd;
	asfd=(struct asfd *)calloc_w(1, sizeof(struct asfd), __func__);
	if(asfd)
		asfd->fd=-1;
	return asfd;
}

void asfd_close(struct asfd *asfd)
{
	if(!asfd) return;
	if(asfd->ssl && asfd->fd>=0)
	{
		set_blocking(asfd->fd);
		// I do not think this SSL_shutdown stuff works right.
		// Ignore it for now.
#ifndef HAVE_WIN32
		signal(SIGPIPE, SIG_IGN);
#endif
		if(!SSL_shutdown(asfd->ssl))
		{
			shutdown(asfd->fd, 1);
			SSL_shutdown(asfd->ssl);
		}
	}
	if(asfd->ssl)
	{
		SSL_free(asfd->ssl);
		asfd->ssl=NULL;
	}
	close_fd(&asfd->fd);
}

static void asfd_free_content(struct asfd *asfd)
{
	asfd_close(asfd);
	iobuf_free(&asfd->rbuf);
	free_w(&asfd->readbuf);
	free_w(&asfd->writebuf);
	free_w(&asfd->desc);
	free_w(&asfd->client);
	free_w(&asfd->listen);
#ifdef USE_IPACL
	ipacl_free(&asfd->ipacl);
#endif
}

void asfd_free(struct asfd **asfd)
{
	if(!asfd || !*asfd) return;
	asfd_free_content(*asfd);
	free_v((void **)asfd);
}

static struct asfd *do_setup_asfd(struct async *as,
	const char *desc, int *fd, const char *listen,
	SSL *ssl, enum asfd_streamtype streamtype)
{
	struct asfd *asfd=NULL;

	if(!fd || *fd<0)
	{
		logp("Given invalid descriptor in %s\n", __func__);
		goto error;
	}

	set_non_blocking(*fd);
	if(!(asfd=asfd_alloc())
	  || asfd_init(asfd, desc, as, *fd, listen, ssl, streamtype))
		goto error;
	*fd=-1;
	as->asfd_add(as, asfd);
	return asfd;
error:
	asfd_free(&asfd);
	return NULL;
}

struct asfd *setup_asfd_ssl(struct async *as,
	const char *desc, int *fd, SSL *ssl)
{
	return do_setup_asfd(as, desc, fd, /*listen*/"",
		ssl, ASFD_STREAM_STANDARD);
}

struct asfd *setup_asfd(struct async *as,
	const char *desc, int *fd, const char *listen)
{
	return do_setup_asfd(as, desc, fd, listen,
		/*ssl*/NULL, ASFD_STREAM_STANDARD);
}

static struct asfd *setup_asfd_linebuf(struct async *as,
	const char *desc, int *fd)
{
	return do_setup_asfd(as, desc, fd, /*listen*/"",
		/*ssl*/NULL, ASFD_STREAM_LINEBUF);
}

struct asfd *setup_asfd_linebuf_read(struct async *as,
	const char *desc, int *fd)
{
	return setup_asfd_linebuf(as, desc, fd);
}

struct asfd *setup_asfd_linebuf_write(struct async *as,
	const char *desc, int *fd)
{
	struct asfd *asfd;
	if((asfd=setup_asfd_linebuf(as, desc, fd)))
		asfd->attempt_reads=0;
	return asfd;
}

static struct asfd *fileno_error(const char *func)
{
	logp("fileno error in %s: %s\n", func, strerror(errno));
	return NULL;
}

struct asfd *setup_asfd_stdin(struct async *as)
{
	int fd=fileno(stdin);
	if(fd<0)
		return fileno_error(__func__);
	return setup_asfd_linebuf_read(as, "stdin", &fd);
}

struct asfd *setup_asfd_stdout(struct async *as)
{
	int fd=fileno(stdout);
	if(fd<0)
		return fileno_error(__func__);
	return setup_asfd_linebuf_write(as, "stdout", &fd);
}

struct asfd *setup_asfd_ncurses_stdin(struct async *as)
{
	int fd=fileno(stdin);
	if(fd<0)
		return fileno_error(__func__);
	return do_setup_asfd(as, "stdin", &fd, /*listen*/"",
		/*ssl=*/NULL, ASFD_STREAM_NCURSES_STDIN);
}

// Want to make sure that we are listening for reads too - this will let us
// exit promptly if the client was killed.
static int read_and_write(struct asfd *asfd)
{
	// Protect against getting stuck in loops where we are trying to
	// flush buffers, but keep getting the same error.
	if(asfd->as->read_write(asfd->as))
		return -1;
	if(!asfd->rbuf->buf) return 0;
	iobuf_log_unexpected(asfd->rbuf, __func__);
	return -1;
}

int asfd_flush_asio(struct asfd *asfd)
{
	while(asfd && asfd->writebuflen>0)
	{
		if(asfd->errors)
			return -1;
		if(read_and_write(asfd))
			return -1;
	}
	return 0;
}

int asfd_write_wrapper(struct asfd *asfd, struct iobuf *wbuf)
{
	while(1)
	{
		if(asfd->errors)
			return -1;
		switch(asfd->append_all_to_write_buffer(asfd, wbuf))
		{
			case APPEND_OK: return 0;
			case APPEND_BLOCKED: break;
			default: return -1;
		}
		if(read_and_write(asfd)) return -1;
	}
	return 0;
}

int asfd_write_wrapper_str(struct asfd *asfd, enum cmd wcmd, const char *wsrc)
{
	static struct iobuf wbuf;
	iobuf_from_str(&wbuf, wcmd, (char *)wsrc);
	return asfd_write_wrapper(asfd, &wbuf);
}

