#include "include.h"

/* For IPTOS / IPTOS_THROUGHPUT */
#ifdef HAVE_WIN32
#include <ws2tcpip.h>
#else
#include <netinet/ip.h>
#endif

static int fd=-1;
static SSL *ssl=NULL;
static float ratelimit=0;
static int network_timeout=0;
static int max_network_timeout=0;
static int doing_estimate=0;

static char *readbuf=NULL;
static size_t readbuflen=0;
static size_t readbufmaxsize=(ASYNC_BUF_LEN*2)+32;

static char *writebuf=NULL;
size_t writebuflen=0;
static size_t writebufmaxsize=(ASYNC_BUF_LEN*2)+32;

int status_wfd=-1; // for the child to send information to the parent.
int status_rfd=-1; // for the child to read information from the parent.

static void truncate_buf(char **buf, size_t *buflen)
{
	(*buf)[0]='\0';
	*buflen=0;
}

static int parse_readbuf(struct iobuf *rbuf)
{
	unsigned int s=0;
	char cmdtmp='\0';

	if(readbuflen>=5)
	{
		if((sscanf(readbuf, "%c%04X", &cmdtmp, &s))!=2)
		{
			logp("sscanf of '%s' failed in parse_readbuf\n",
				readbuf);
			truncate_buf(&readbuf, &readbuflen);
			return -1;
		}
	}
	if(readbuflen>=s+5)
	{
		rbuf->cmd=cmdtmp;
		if(!(rbuf->buf=(char *)malloc(s+1)))
		{
			log_out_of_memory(__FUNCTION__);
			truncate_buf(&readbuf, &readbuflen);
			return -1;
		}
		if(!(memcpy(rbuf->buf, readbuf+5, s)))
		{
			logp("memcpy failed in parse_readbuf\n");
			truncate_buf(&readbuf, &readbuflen);
			return -1;
		}
		rbuf->buf[s]='\0';
		if(!(memmove(readbuf, readbuf+s+5, readbuflen-s-5)))
		{
			logp("memmove failed in parse_readbuf\n");
			truncate_buf(&readbuf, &readbuflen);
			return -1;
		}
		readbuflen-=s+5;
		rbuf->len=s;
	}
	return 0;
}

static int async_alloc_buf(char **buf, size_t *buflen, size_t bufmaxsize)
{
	if(!*buf)
	{
		if(!(*buf=(char *)malloc(bufmaxsize)))
		{
			log_out_of_memory(__FUNCTION__);
			return -1;
		}
		truncate_buf(buf, buflen);
	}
	return 0;
}

static int do_read(int *read_blocked_on_write)
{
	ssize_t r;

	ERR_clear_error();
	r=SSL_read(ssl, readbuf+readbuflen, readbufmaxsize-readbuflen);

	switch(SSL_get_error(ssl, r))
	{
	  case SSL_ERROR_NONE:
		//logp("read: %d\n", r);
		readbuflen+=r;
		readbuf[readbuflen]='\0';
		break;
	  case SSL_ERROR_ZERO_RETURN:
		/* end of data */
		//logp("zero return!\n");
		SSL_shutdown(ssl);
		truncate_buf(&readbuf, &readbuflen);
		return -1;
	  case SSL_ERROR_WANT_READ:
		break;
	  case SSL_ERROR_WANT_WRITE:
		*read_blocked_on_write=1;
		break;
	  case SSL_ERROR_SYSCALL:
		if(errno == EAGAIN || errno == EINTR)
			break;
		logp("Got SSL_ERROR_SYSCALL in read, errno=%d (%s)\n",
			errno, strerror(errno));
		// Fall through to read problem
	  default:
		logp("SSL read problem\n");
		truncate_buf(&readbuf, &readbuflen);
		return -1;
	}
	return 0;
}

// Return 0 for OK to write, non-zero for not OK to write.
static int check_ratelimit(unsigned long long *bytes)
{
	float f;
	time_t now;
	time_t diff;
	static time_t start=time(NULL);
	static int sleeptime=10000;
	now=time(NULL);
	if((diff=now-start)<0)
	{
		// It is possible that the clock changed. Reset ourselves.
		now=start;
		*bytes=0;
		logp("Looks like the clock went back in time since starting. Resetting ratelimit\n");
		return 0;
	}
	if(!diff) return 0; // Need to get started somehow.
	f=(*bytes)/diff; // Bytes per second.

	if(f>=ratelimit)
	{
	//	printf("ratelimit: %f %f\n", f, ratelimit);
#ifdef HAVE_WIN32
		// Windows Sleep is milliseconds, usleep is microseconds.
		// Do some conversion.
		Sleep(sleeptime/1000);
#else
		usleep(sleeptime);
#endif
		// If sleeping, increase the sleep time.
		if((sleeptime*=2)>=500000) sleeptime=500000;
		return 1;
	}
	// If not sleeping, decrease the sleep time.
	if((sleeptime/=2)<=9999) sleeptime=10000;
	return 0;
}

static int do_write(int *write_blocked_on_read)
{
	ssize_t w;
	static unsigned long long bytes=0;

	if(ratelimit && check_ratelimit(&bytes)) return 0;
	ERR_clear_error();
	w=SSL_write(ssl, writebuf, writebuflen);

	switch(SSL_get_error(ssl, w))
	{
	  case SSL_ERROR_NONE:
		//logp("wrote: %d\n", w);
/*
char msg[1024];
snprintf(msg, writebuflen, "%s", writebuf);
logp("want : %s\n", msg);
snprintf(msg, w, "%s", writebuf);
logp("wrote: %s\n", msg);
*/
		if(ratelimit) bytes+=w;
		memmove(writebuf, writebuf+w, writebuflen-w);
		writebuflen-=w;
		break;
	  case SSL_ERROR_WANT_WRITE:
		break;
	  case SSL_ERROR_WANT_READ:
		*write_blocked_on_read=1;
		break;
	  case SSL_ERROR_SYSCALL:
		if(errno == EAGAIN || errno == EINTR)
			break;
		logp("Got SSL_ERROR_SYSCALL in write, errno=%d (%s)\n",
			errno, strerror(errno));
		// Fall through to write problem
	  default:
		berr_exit("SSL write problem");
		logp("write returned: %d\n", w);
		return -1;
	}
	return 0;
}

static int append_to_write_buffer(const char *buf, size_t len)
{
	memcpy(writebuf+writebuflen, buf, len);
	writebuflen+=len;
	writebuf[writebuflen]='\0';
	return 0;
}

int async_append_all_to_write_buffer(struct iobuf *wbuf)
{
	size_t sblen=0;
	char sbuf[10]="";
	if(writebuflen+6+(wbuf->len) >= writebufmaxsize-1)
		return 1;

	snprintf(sbuf, sizeof(sbuf), "%c%04X",
		wbuf->cmd, (unsigned int)wbuf->len);
	sblen=strlen(sbuf);
	append_to_write_buffer(sbuf, sblen);
	append_to_write_buffer(wbuf->buf, wbuf->len);
//{
//	char msg[256]="";
//	snprintf(msg, wbuf->len+1, "%s", wbuf->buf);
//	printf("appended to wbuf: %c (%d) (%d) %s\n",
//		wbuf->cmd, wbuf->len+sblen, writebuflen, msg);
//}
	wbuf->len=0;
	return 0;
}

int async_init(int afd, SSL *assl, struct config *conf, int estimate)
{
	fd=afd;
	ssl=assl;
	ratelimit=conf->ratelimit;
	max_network_timeout=conf->network_timeout;
	network_timeout=max_network_timeout;
	doing_estimate=estimate;
	if(doing_estimate) return 0;

	if(async_alloc_buf(&readbuf, &readbuflen, readbufmaxsize)
	  || async_alloc_buf(&writebuf, &writebuflen, writebufmaxsize))
		return -1;
	return 0;

}

int set_bulk_packets(void)
{
#if defined(IP_TOS) && defined(IPTOS_THROUGHPUT)
	int opt=IPTOS_THROUGHPUT;
	if(fd<0) return -1;
	if(setsockopt(fd, IPPROTO_IP, IP_TOS, (char *) &opt, sizeof(opt))<0)
	{
		logp("Error: setsockopt IPTOS_THROUGHPUT: %s\n",
			strerror(errno));
		return -1;
	}
#endif
	return 0;
}

void async_free(void)
{
//	printf("in async_free\n");
	if(ssl && fd>=0)
	{
		int r;
		//int x;
		set_blocking(fd);
/* I do not think this SSL_shutdown stuff works right. Ignore it for now. */
//printf("calling SSL_shutdown...\n");
#ifndef HAVE_WIN32
signal(SIGPIPE, SIG_IGN);
#endif
		if(!(r=SSL_shutdown(ssl)))
		{
//printf("calling SSL_shutdown again...\n");
			shutdown(fd, 1);
			r=SSL_shutdown(ssl);
		}
/*
		switch(r)
		{
			case 1:
				printf("SSL shutdown OK\n");
				break; // success
			case 0:
			case -1:
			default:
				switch(x=SSL_get_error(ssl, r))
				{
					case SSL_ERROR_NONE:
						printf("A!\n"); break;
					case SSL_ERROR_ZERO_RETURN:
						printf("B!\n"); break;
					case SSL_ERROR_WANT_READ:
						printf("C!\n");
						do_read(&r);
						break;
					case SSL_ERROR_WANT_WRITE:
						printf("D!\n"); break;
					default:
						printf("Z: %d!\n", x); break;
				}
				printf("SSL shutdown failed: %d\n", r);
		}
*/
	}
	if(ssl)
	{
		SSL_free(ssl);
		ssl=NULL;
	}
	close_fd(&fd);
	readbuflen=0;
	writebuflen=0;
	if(readbuf) { free(readbuf); readbuf=NULL; }
	if(writebuf) { free(writebuf); writebuf=NULL; }
}

/* for debug purposes */
static int setsec=1;
static int setusec=0;

void settimers(int sec, int usec)
{
	setsec=sec;
	setusec=usec;
}

int async_rw(struct iobuf *rbuf, struct iobuf *wbuf)
{
        int mfd=-1;
        fd_set fsr;
        fd_set fsw;
        fd_set fse;
	int doread=0;
	int dowrite=0;
        struct timeval tval;
	static int read_blocked_on_write=0;
	static int write_blocked_on_read=0;

//printf("in async_rw\n");
	if(doing_estimate) return 0;

	if(fd<0)
	{
		logp("fd not ready in async rw: %d\n", fd);
		return -1;
	}

	if(rbuf) doread++;

	if(wbuf && wbuf->len)
		async_append_all_to_write_buffer(wbuf);

	if(writebuflen && !write_blocked_on_read)
		dowrite++; // The write buffer is not yet empty.

	if(doread)
	{
		if(parse_readbuf(rbuf))
		{
			logp("error in parse_readbuf\n");
			return -1;
		}
		if(rbuf->buf) return 0;

		if(read_blocked_on_write) doread=0;
	}

        if(doread || dowrite)
        {
//logp("async_rw loop read %d write %d wbuflen: %d\n", doread, dowrite, writebuflen);
                mfd=-1;

                if(doread) FD_ZERO(&fsr);
                if(dowrite) FD_ZERO(&fsw);
                FD_ZERO(&fse);

                add_fd_to_sets(fd,
			doread?&fsr:NULL, dowrite?&fsw:NULL, &fse, &mfd);

                tval.tv_sec=setsec;
                tval.tv_usec=setusec;

                if(select(mfd+1,
			doread?&fsr:NULL, dowrite?&fsw:NULL, &fse, &tval)<0)
                {
                        if(errno!=EAGAIN && errno!=EINTR)
                        {
                                logp("select error in %s: %s\n", __func__,
					strerror(errno));
                                return -1;
                        }
                }

		if(!FD_ISSET(fd, &fse)
		  && (!doread || !FD_ISSET(fd, &fsr))
		  && (!dowrite || !FD_ISSET(fd, &fsw)))
		{
			//printf("SELECT HIT TIMEOUT - doread: %d, dowrite: %d\n",
			//	doread, dowrite);
			//printf("%d %d\n", readbuflen, writebuflen);
			// Be careful to avoid 'read quick' mode.
			if((setsec || setusec)
			  && max_network_timeout>0 && network_timeout--<=0)
			{
				logp("No activity on network for %d seconds.\n",
					max_network_timeout);
				return -1;
			}
			return 0;
		}
		network_timeout=max_network_timeout;

                if(FD_ISSET(fd, &fse))
                {
                        logp("error on socket\n");
                        return -1;
                }

                if(doread && FD_ISSET(fd, &fsr)) // able to read
                {
			int r;
			read_blocked_on_write=0;
			if(do_read(&read_blocked_on_write)) return -1;
			if((r=parse_readbuf(rbuf)))
				logp("error in second parse_readbuf\n");
//printf("read: %c:%s\n", rbuf->cmd, rbuf->buf);
			return r;
                }

                if(dowrite && FD_ISSET(fd, &fsw)) // able to write
		{
			int r=0;
			write_blocked_on_read=0;

			if((r=do_write(&write_blocked_on_read)))
				logp("error in do_write\n");
//printf("did write\n");
			return r;
		}
        }

        return 0;
}

static int async_rw_ensure_read(struct iobuf *rbuf, struct iobuf *wbuf)
{
	if(doing_estimate) return 0;
	while(!rbuf->buf) if(async_rw(rbuf, wbuf)) return -1;
	return 0;
}

static int async_rw_ensure_write(struct iobuf *rbuf, struct iobuf *wbuf)
{
	if(doing_estimate) return 0;
	while(wbuf->len) if(async_rw(rbuf, wbuf)) return -1;
	return 0;
}

int async_read_quick(struct iobuf *rbuf)
{
	int r;
	int savesec=setsec;
	int saveusec=setusec;
	setsec=0;
	setusec=0;
	r=async_rw(rbuf, NULL);
	setsec=savesec;
	setusec=saveusec;
	return r;
}

int async_read(struct iobuf *rbuf)
{
	return async_rw_ensure_read(rbuf, NULL);
}

int async_write(struct iobuf *wbuf)
{
	return async_rw_ensure_write(NULL, wbuf);
}

int async_write_strn(char wcmd, const char *wsrc, size_t len)
{
	struct iobuf wbuf;
	wbuf.cmd=wcmd;
	wbuf.buf=(char *)wsrc;
	wbuf.len=len;
	return async_write(&wbuf);
}

int async_write_str(char wcmd, const char *wsrc)
{
	return async_write_strn(wcmd, wsrc, strlen(wsrc));
}

int async_read_expect(char cmd, const char *expect)
{
	int ret=0;
	struct iobuf rbuf;
	iobuf_init(&rbuf);
	if(async_read(&rbuf)) return -1;
	if(rbuf.cmd!=cmd || strcmp(rbuf.buf, expect))
	{
		logp("expected '%c:%s', got '%c:%s'\n",
			cmd, expect, rbuf.cmd, rbuf.buf);
		ret=-1;
	}
	iobuf_free_content(&rbuf);
	return ret;
}

int async_simple_loop(struct config *conf, void *param, const char *caller,
  enum asl_ret callback(struct iobuf *rbuf, struct config *conf, void *param))
{
	static struct iobuf *rbuf=NULL;
	if(!rbuf && !(rbuf=iobuf_alloc()))
		return -1;
	while(1)
	{
		iobuf_free_content(rbuf);
		if(async_read(rbuf)) return -1;
		if(rbuf->cmd!=CMD_GEN)
		{
			if(rbuf->cmd==CMD_WARNING)
			{
				logp("WARNING: %s\n", rbuf->buf);
				do_filecounter(conf->cntr, rbuf->cmd, 0);
			}
			else if(rbuf->cmd==CMD_INTERRUPT)
			{
				// Ignore - client wanted to interrupt a file.
			}
			else
			{
				logp("unexpected command in %s(), called from %s(): %c:%s\n", __FUNCTION__, caller, rbuf->cmd, rbuf->buf);
				return -1;
			}
			continue;
		}
		switch(callback(rbuf, conf, param))
		{
			case ASL_CONTINUE: break;
			case ASL_END_OK: return 0;
			case ASL_END_OK_RETURN_1: return 1;
			case ASL_END_ERROR:
			default:
				return -1;
		}
	}
	return -1; // Not reached.
}

void log_and_send(const char *msg)
{
	logp("%s\n", msg);
	if(fd>0) async_write_str(CMD_ERROR, msg);
}

void log_and_send_oom(const char *function)
{
	char m[256]="";
	snprintf(m, sizeof(m), "out of memory in %s()\n", __FUNCTION__);
	logp("%s", m);
	if(fd>0) async_write_str(CMD_ERROR, m);
}

int async_get_fd(void)
{
	return fd;
}

// should be in src/lib/log.c
int logw(struct cntr *cntr, const char *fmt, ...)
{
	int r=0;
	char buf[512]="";
	va_list ap;
	va_start(ap, fmt);
	vsnprintf(buf, sizeof(buf), fmt, ap);
	if(doing_estimate) printf("\nWARNING: %s\n", buf);
	else
	{
		r=async_write_str(CMD_WARNING, buf);
		logp("WARNING: %s\n", buf);
	}
	va_end(ap);
	do_filecounter(cntr, CMD_WARNING, 1);
	return r;
}
