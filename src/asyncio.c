#include "include.h"

/* For IPTOS / IPTOS_THROUGHPUT */
#ifdef HAVE_WIN32
#include <ws2tcpip.h>
#else
#include <netinet/ip.h>
#endif

static size_t bufmaxsize=(ASYNC_BUF_LEN*2)+32;

int status_wfd=-1; // for the child to send information to the parent.
int status_rfd=-1; // for the child to read information from the parent.

static void truncate_buf(char **buf, size_t *buflen)
{
	(*buf)[0]='\0';
	*buflen=0;
}

static int parse_readbuf(struct async *as, struct iobuf *rbuf)
{
	unsigned int s=0;
	char cmdtmp='\0';

	if(as->readbuflen>=5)
	{
		if((sscanf(as->readbuf, "%c%04X", &cmdtmp, &s))!=2)
		{
			logp("sscanf of '%s' failed in %s\n",
				as->readbuf, __func__);
			truncate_buf(&as->readbuf, &as->readbuflen);
			return -1;
		}
	}
	if(as->readbuflen>=s+5)
	{
		rbuf->cmd=cmdtmp;
		if(!(rbuf->buf=(char *)malloc(s+1)))
		{
			log_out_of_memory(__func__);
			truncate_buf(&as->readbuf, &as->readbuflen);
			return -1;
		}
		if(!(memcpy(rbuf->buf, as->readbuf+5, s)))
		{
			logp("memcpy failed in %s\n", __func__);
			truncate_buf(&as->readbuf, &as->readbuflen);
			return -1;
		}
		rbuf->buf[s]='\0';
		if(!(memmove(as->readbuf, as->readbuf+s+5, as->readbuflen-s-5)))
		{
			logp("memmove failed in %s\n", __func__);
			truncate_buf(&as->readbuf, &as->readbuflen);
			return -1;
		}
		as->readbuflen-=s+5;
		rbuf->len=s;
	}
	return 0;
}

static int async_alloc_buf(char **buf, size_t *buflen)
{
	if(!*buf && !(*buf=(char *)malloc(bufmaxsize)))
	{
		log_out_of_memory(__func__);
		return -1;
	}
	truncate_buf(buf, buflen);
	return 0;
}

static int do_read(struct async *as)
{
	ssize_t r;
	r=read(as->fd, as->readbuf+as->readbuflen, bufmaxsize-as->readbuflen);
	if(r<0)
	{
		if(errno==EAGAIN || errno==EINTR)
			return 0;
		logp("read problem in %s\n", __func__);
		truncate_buf(&as->readbuf, &as->readbuflen);
		return -1;
	}
	else if(!r)
	{
		// End of data.
		logp("end of data in %s\n", __func__);
		truncate_buf(&as->readbuf, &as->readbuflen);
		return -1;
	}
	as->readbuflen+=r;
	as->readbuf[as->readbuflen]='\0';
	return 0;
}

static int do_read_ssl(struct async *as)
{
	ssize_t r;

	ERR_clear_error();
	r=SSL_read(as->ssl,
		as->readbuf+as->readbuflen, bufmaxsize-as->readbuflen);

	switch(SSL_get_error(as->ssl, r))
	{
	  case SSL_ERROR_NONE:
		as->readbuflen+=r;
		as->readbuf[as->readbuflen]='\0';
		break;
	  case SSL_ERROR_ZERO_RETURN:
		// End of data.
		SSL_shutdown(as->ssl);
		truncate_buf(&as->readbuf, &as->readbuflen);
		return -1;
	  case SSL_ERROR_WANT_READ:
		break;
	  case SSL_ERROR_WANT_WRITE:
		as->read_blocked_on_write=1;
		break;
	  case SSL_ERROR_SYSCALL:
		if(errno==EAGAIN || errno==EINTR)
			break;
		logp("Got SSL_ERROR_SYSCALL in read, errno=%d (%s)\n",
			errno, strerror(errno));
		// Fall through to read problem
	  default:
		logp("SSL read problem in %s\n", __func__);
		truncate_buf(&as->readbuf, &as->readbuflen);
		return -1;
	}
	return 0;
}

// Return 0 for OK to write, non-zero for not OK to write.
static int check_ratelimit(struct async *as)
{
	float f;
	time_t now;
	time_t diff;
	if(!as->rlstart) as->rlstart=time(NULL);
	now=time(NULL);
	if((diff=now-as->rlstart)<0)
	{
		// It is possible that the clock changed. Reset ourselves.
		now=as->rlstart;
		as->rlbytes=0;
		logp("Looks like the clock went back in time since starting. "
			"Resetting ratelimit\n");
		return 0;
	}
	if(!diff) return 0; // Need to get started somehow.
	f=(as->rlbytes)/diff; // Bytes per second.

	if(f>=as->ratelimit)
	{
#ifdef HAVE_WIN32
		// Windows Sleep is milliseconds, usleep is microseconds.
		// Do some conversion.
		Sleep(as->rlsleeptime/1000);
#else
		usleep(as->rlsleeptime);
#endif
		// If sleeping, increase the sleep time.
		if((as->rlsleeptime*=2)>=500000) as->rlsleeptime=500000;
		return 1;
	}
	// If not sleeping, decrease the sleep time.
	if((as->rlsleeptime/=2)<=9999) as->rlsleeptime=10000;
	return 0;
}

static int do_write(struct async *as)
{
	ssize_t w;
	if(as->ratelimit && check_ratelimit(as)) return 0;

	w=write(as->fd, as->writebuf, as->writebuflen);
	if(w<0)
	{
		if(errno==EAGAIN || errno==EINTR)
			return 0;
		logp("Got error in %s, errno=%d (%s)\n", __func__,
			errno, strerror(errno));
		return -1;
	}
	else if(!w)
	{
		logp("Wrote nothing in %s\n", __func__);
		return -1;
	}
	if(as->ratelimit) as->rlbytes+=w;
	memmove(as->writebuf, as->writebuf+w, as->writebuflen-w);
	as->writebuflen-=w;
	return 0;
}

static int do_write_ssl(struct async *as)
{
	ssize_t w;

	if(as->ratelimit && check_ratelimit(as)) return 0;
	ERR_clear_error();
	w=SSL_write(as->ssl, as->writebuf, as->writebuflen);

	switch(SSL_get_error(as->ssl, w))
	{
	  case SSL_ERROR_NONE:
		if(as->ratelimit) as->rlbytes+=w;
		memmove(as->writebuf, as->writebuf+w, as->writebuflen-w);
		as->writebuflen-=w;
		break;
	  case SSL_ERROR_WANT_WRITE:
		break;
	  case SSL_ERROR_WANT_READ:
		as->write_blocked_on_read=1;
		break;
	  case SSL_ERROR_SYSCALL:
		if(errno==EAGAIN || errno==EINTR)
			break;
		logp("Got SSL_ERROR_SYSCALL in %s, errno=%d (%s)\n", __func__,
			errno, strerror(errno));
		// Fall through to write problem
	  default:
		berr_exit("SSL write problem");
		logp("write returned: %d\n", w);
		return -1;
	}
	return 0;
}

static int append_to_write_buffer(struct async *as,
	const char *buf, size_t len)
{
	memcpy(as->writebuf+as->writebuflen, buf, len);
	as->writebuflen+=len;
	as->writebuf[as->writebuflen]='\0';
	return 0;
}

static int async_append_all_to_write_buffer(struct async *as,
	struct iobuf *wbuf)
{
	size_t sblen=0;
	char sbuf[10]="";
	if(as->writebuflen+6+(wbuf->len) >= bufmaxsize-1)
		return 1;

	snprintf(sbuf, sizeof(sbuf), "%c%04X",
		wbuf->cmd, (unsigned int)wbuf->len);
	sblen=strlen(sbuf);
	append_to_write_buffer(as, sbuf, sblen);
	append_to_write_buffer(as, wbuf->buf, wbuf->len);
	wbuf->len=0;
	return 0;
}

static int async_set_bulk_packets(struct async *as)
{
#if defined(IP_TOS) && defined(IPTOS_THROUGHPUT)
	int opt=IPTOS_THROUGHPUT;
	if(as->fd<0) return -1;
	if(setsockopt(as->fd, IPPROTO_IP, IP_TOS, (char *)&opt, sizeof(opt))<0)
	{
		logp("Error: setsockopt IPTOS_THROUGHPUT: %s\n",
			strerror(errno));
		return -1;
	}
#endif
	return 0;
}

void async_free(struct async **as)
{
	int fd;
	SSL *ssl;
	if(!*as) return;
	fd=(*as)->fd;
	ssl=(*as)->ssl;
	if(ssl && fd>=0)
	{
		int r;
		set_blocking(fd);
		// I do not think this SSL_shutdown stuff works right.
		// Ignore it for now.
#ifndef HAVE_WIN32
signal(SIGPIPE, SIG_IGN);
#endif
		if(!(r=SSL_shutdown(ssl)))
		{
			shutdown(fd, 1);
			r=SSL_shutdown(ssl);
		}
	}
	if(ssl)
	{
		SSL_free(ssl);
		(*as)->ssl=NULL;
	}
	close_fd(&((*as)->fd));
	if((*as)->readbuf) free((*as)->readbuf);
	if((*as)->writebuf) free((*as)->writebuf);
	free(*as);
	*as=NULL;
}

static void async_settimers(struct async *as, int sec, int usec)
{
	as->setsec=sec;
	as->setusec=usec;
}

static int async_rw(struct async *as, struct iobuf *rbuf, struct iobuf *wbuf)
{
        int mfd=-1;
        fd_set fsr;
        fd_set fsw;
        fd_set fse;
	int doread=0;
	int dowrite=0;
        struct timeval tval;

	if(as->doing_estimate) return 0;

	if(as->fd<0)
	{
		logp("fd not ready in %s: %d\n", __func__, as->fd);
		return -1;
	}

	if(rbuf) doread++;

	if(wbuf && wbuf->len)
		async_append_all_to_write_buffer(as, wbuf);

	if(as->writebuflen && !as->write_blocked_on_read)
		dowrite++; // The write buffer is not yet empty.

	if(doread)
	{
		if(parse_readbuf(as, rbuf)) return -1;
		if(rbuf->buf) return 0;

		if(as->read_blocked_on_write) doread=0;
	}

        if(doread || dowrite)
        {
                mfd=-1;

                if(doread) FD_ZERO(&fsr);
                if(dowrite) FD_ZERO(&fsw);
                FD_ZERO(&fse);

                add_fd_to_sets(as->fd,
			doread?&fsr:NULL, dowrite?&fsw:NULL, &fse, &mfd);

                tval.tv_sec=as->setsec;
                tval.tv_usec=as->setusec;

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

		if(!FD_ISSET(as->fd, &fse)
		  && (!doread || !FD_ISSET(as->fd, &fsr))
		  && (!dowrite || !FD_ISSET(as->fd, &fsw)))
		{
			// Be careful to avoid 'read quick' mode.
			if((as->setsec || as->setusec)
			  && as->max_network_timeout>0
			  && as->network_timeout--<=0)
			{
				logp("No activity on network for %d seconds.\n",
					as->max_network_timeout);
				return -1;
			}
			return 0;
		}
		as->network_timeout=as->max_network_timeout;

                if(FD_ISSET(as->fd, &fse))
                {
                        logp("error on socket\n");
                        return -1;
                }

                if(doread && FD_ISSET(as->fd, &fsr)) // able to read
                {
			if(as->ssl)
			{
				as->read_blocked_on_write=0;
				if(do_read_ssl(as)) return -1;
			}
			else
			{
				if(do_read(as)) return -1;
			}
			return parse_readbuf(as, rbuf);
                }

                if(dowrite && FD_ISSET(as->fd, &fsw)) // able to write
		{
			if(as->ssl)
			{
				as->write_blocked_on_read=0;
				return do_write_ssl(as);
			}
			else
				return do_write(as);
		}
        }

        return 0;
}

static int async_read(struct async *as, struct iobuf *rbuf)
{
	if(as->doing_estimate) return 0;
	while(!rbuf->buf) if(async_rw(as, rbuf, NULL)) return -1;
	return 0;
}

static int async_write(struct async *as, struct iobuf *wbuf)
{
	if(as->doing_estimate) return 0;
	while(wbuf->len) if(async_rw(as, NULL, wbuf)) return -1;
	return 0;
}

static int async_read_quick(struct async *as, struct iobuf *rbuf)
{
	int r;
	int savesec=as->setsec;
	int saveusec=as->setusec;
	as->setsec=0;
	as->setusec=0;
	r=as->rw(as, rbuf, NULL);
	as->setsec=savesec;
	as->setusec=saveusec;
	return r;
}

static int async_write_strn(struct async *as,
	char wcmd, const char *wsrc, size_t len)
{
	struct iobuf wbuf;
	wbuf.cmd=wcmd;
	wbuf.buf=(char *)wsrc;
	wbuf.len=len;
	return async_write(as, &wbuf);
}

static int async_write_str(struct async *as, char wcmd, const char *wsrc)
{
	return async_write_strn(as, wcmd, wsrc, strlen(wsrc));
}

static int async_read_expect(struct async *as, char cmd, const char *expect)
{
	int ret=0;
	struct iobuf rbuf;
	iobuf_init(&rbuf);
	if(async_read(as, &rbuf)) return -1;
	if(rbuf.cmd!=cmd || strcmp(rbuf.buf, expect))
	{
		logp("expected '%c:%s', got '%c:%s'\n",
			cmd, expect, rbuf.cmd, rbuf.buf);
		ret=-1;
	}
	iobuf_free_content(&rbuf);
	return ret;
}

static int async_simple_loop(struct async *as,
	struct conf *conf, void *param, const char *caller,
  enum asl_ret callback(struct async *as,
	struct iobuf *rbuf, struct conf *conf, void *param))
{
	static struct iobuf *rbuf=NULL;
	if(!rbuf && !(rbuf=iobuf_alloc()))
		return -1;
	while(1)
	{
		iobuf_free_content(rbuf);
		if(async_read(as, rbuf)) return -1;
		if(rbuf->cmd!=CMD_GEN)
		{
			if(rbuf->cmd==CMD_WARNING)
			{
				logp("WARNING: %s\n", rbuf->buf);
				cntr_add(conf->cntr, rbuf->cmd, 0);
			}
			else if(rbuf->cmd==CMD_INTERRUPT)
			{
				// Ignore - client wanted to interrupt a file.
			}
			else
			{
				logp("unexpected command in %s(), called from %s(): %c:%s\n", __func__, caller, rbuf->cmd, rbuf->buf);
				return -1;
			}
			continue;
		}
		switch(callback(as, rbuf, conf, param))
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

static int async_init(struct async *as,
	int afd, SSL *assl, struct conf *conf, int estimate)
{
	as->fd=afd;
	as->ssl=assl;
	as->max_network_timeout=conf->network_timeout;
	as->network_timeout=as->max_network_timeout;
	as->ratelimit=conf->ratelimit;
	as->rlsleeptime=10000;

	as->rw=async_rw;
	as->read=async_read;
	as->write=async_write;
	as->read_quick=async_read_quick;

	as->setsec=1;
	as->setusec=0;

	as->write_strn=async_write_strn;
	as->write_str=async_write_str;
	as->read_expect=async_read_expect;
	as->append_all_to_write_buffer=async_append_all_to_write_buffer;
	as->set_bulk_packets=async_set_bulk_packets;
	as->simple_loop=async_simple_loop;
	as->settimers=async_settimers;

	if((as->doing_estimate=estimate)) return 0;

	if(async_alloc_buf(&as->readbuf, &as->readbuflen)
	  || async_alloc_buf(&as->writebuf, &as->writebuflen))
		return -1;
	return 0;
}

struct async *async_alloc(void)
{
	struct async *as;
	if(!(as=(struct async *)calloc(1, sizeof(struct async))))
		log_out_of_memory(__func__);
	else
		as->init=async_init;
	return as;
}
