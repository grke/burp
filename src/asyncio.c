#include "include.h"

/* For IPTOS / IPTOS_THROUGHPUT */
#ifdef HAVE_WIN32
#include <ws2tcpip.h>
#else
#include <netinet/ip.h>
#endif

static size_t bufmaxsize=(ASYNC_BUF_LEN*2)+32;

static void truncate_buf(char **buf, size_t *buflen)
{
	(*buf)[0]='\0';
	*buflen=0;
}

static int parse_readbuf(struct asfd *asfd, struct iobuf *rbuf)
{
	unsigned int s=0;
	char cmdtmp='\0';

	if(asfd->readbuflen>=5)
	{
		if((sscanf(asfd->readbuf, "%c%04X", &cmdtmp, &s))!=2)
		{
			logp("sscanf of '%s' failed in %s\n",
				asfd->readbuf, __func__);
			truncate_buf(&asfd->readbuf, &asfd->readbuflen);
			return -1;
		}
	}
	if(asfd->readbuflen>=s+5)
	{
		rbuf->cmd=cmdtmp;
		if(!(rbuf->buf=(char *)malloc(s+1)))
		{
			log_out_of_memory(__func__);
			truncate_buf(&asfd->readbuf, &asfd->readbuflen);
			return -1;
		}
		if(!(memcpy(rbuf->buf, asfd->readbuf+5, s)))
		{
			logp("memcpy failed in %s\n", __func__);
			truncate_buf(&asfd->readbuf, &asfd->readbuflen);
			return -1;
		}
		rbuf->buf[s]='\0';
		if(!(memmove(asfd->readbuf,
			asfd->readbuf+s+5, asfd->readbuflen-s-5)))
		{
			logp("memmove failed in %s\n", __func__);
			truncate_buf(&asfd->readbuf, &asfd->readbuflen);
			return -1;
		}
		asfd->readbuflen-=s+5;
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

static int do_read(struct asfd *asfd)
{
	ssize_t r;
	r=read(asfd->fd,
		asfd->readbuf+asfd->readbuflen, bufmaxsize-asfd->readbuflen);
	if(r<0)
	{
		if(errno==EAGAIN || errno==EINTR)
			return 0;
		logp("read problem in %s\n", __func__);
		truncate_buf(&asfd->readbuf, &asfd->readbuflen);
		return -1;
	}
	else if(!r)
	{
		// End of data.
		logp("end of data in %s\n", __func__);
		truncate_buf(&asfd->readbuf, &asfd->readbuflen);
		return -1;
	}
	asfd->readbuflen+=r;
	asfd->readbuf[asfd->readbuflen]='\0';
	return 0;
}

static int do_read_ssl(struct asfd *asfd)
{
	ssize_t r;

	ERR_clear_error();
	r=SSL_read(asfd->ssl,
		asfd->readbuf+asfd->readbuflen, bufmaxsize-asfd->readbuflen);

	switch(SSL_get_error(asfd->ssl, r))
	{
	  case SSL_ERROR_NONE:
		asfd->readbuflen+=r;
		asfd->readbuf[asfd->readbuflen]='\0';
		break;
	  case SSL_ERROR_ZERO_RETURN:
		// End of data.
		SSL_shutdown(asfd->ssl);
		truncate_buf(&asfd->readbuf, &asfd->readbuflen);
		return -1;
	  case SSL_ERROR_WANT_READ:
		break;
	  case SSL_ERROR_WANT_WRITE:
		asfd->read_blocked_on_write=1;
		break;
	  case SSL_ERROR_SYSCALL:
		if(errno==EAGAIN || errno==EINTR)
			break;
		logp("Got SSL_ERROR_SYSCALL in read, errno=%d (%s)\n",
			errno, strerror(errno));
		// Fall through to read problem
	  default:
		logp("SSL read problem in %s\n", __func__);
		truncate_buf(&asfd->readbuf, &asfd->readbuflen);
		return -1;
	}
	return 0;
}

// Return 0 for OK to write, non-zero for not OK to write.
static int check_ratelimit(struct asfd *asfd)
{
	float f;
	time_t now;
	time_t diff;
	if(!asfd->rlstart) asfd->rlstart=time(NULL);
	now=time(NULL);
	if((diff=now-asfd->rlstart)<0)
	{
		// It is possible that the clock changed. Reset ourselves.
		now=asfd->rlstart;
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

static int do_write(struct asfd *asfd)
{
	ssize_t w;
	if(asfd->ratelimit && check_ratelimit(asfd)) return 0;

	w=write(asfd->fd, asfd->writebuf, asfd->writebuflen);
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
	if(asfd->ratelimit) asfd->rlbytes+=w;
	memmove(asfd->writebuf, asfd->writebuf+w, asfd->writebuflen-w);
	asfd->writebuflen-=w;
	return 0;
}

static int do_write_ssl(struct asfd *asfd)
{
	ssize_t w;

	if(asfd->ratelimit && check_ratelimit(asfd)) return 0;
	ERR_clear_error();
	w=SSL_write(asfd->ssl, asfd->writebuf, asfd->writebuflen);

	switch(SSL_get_error(asfd->ssl, w))
	{
	  case SSL_ERROR_NONE:
		if(asfd->ratelimit) asfd->rlbytes+=w;
		memmove(asfd->writebuf, asfd->writebuf+w, asfd->writebuflen-w);
		asfd->writebuflen-=w;
		break;
	  case SSL_ERROR_WANT_WRITE:
		break;
	  case SSL_ERROR_WANT_READ:
		asfd->write_blocked_on_read=1;
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

static int append_to_write_buffer(struct asfd *asfd,
	const char *buf, size_t len)
{
	memcpy(asfd->writebuf+asfd->writebuflen, buf, len);
	asfd->writebuflen+=len;
	asfd->writebuf[asfd->writebuflen]='\0';
	return 0;
}

static int asfd_append_all_to_write_buffer(struct asfd *asfd,
	struct iobuf *wbuf)
{
	size_t sblen=0;
	char sbuf[10]="";
	if(asfd->writebuflen+6+(wbuf->len) >= bufmaxsize-1)
		return 1;

	snprintf(sbuf, sizeof(sbuf), "%c%04X",
		wbuf->cmd, (unsigned int)wbuf->len);
	sblen=strlen(sbuf);
	append_to_write_buffer(asfd, sbuf, sblen);
	append_to_write_buffer(asfd, wbuf->buf, wbuf->len);
	wbuf->len=0;
	return 0;
}

static int asfd_set_bulk_packets(struct asfd *asfd)
{
#if defined(IP_TOS) && defined(IPTOS_THROUGHPUT)
	int opt=IPTOS_THROUGHPUT;
	if(asfd->fd<0) return -1;
	if(setsockopt(asfd->fd,
		IPPROTO_IP, IP_TOS, (char *)&opt, sizeof(opt))<0)
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
	fd=(*as)->asfd->fd;
	ssl=(*as)->asfd->ssl;
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
		(*as)->asfd->ssl=NULL;
	}
	close_fd(&((*as)->asfd->fd));
	if((*as)->asfd->readbuf) free((*as)->asfd->readbuf);
	if((*as)->asfd->writebuf) free((*as)->asfd->writebuf);
	free((*as)->asfd);
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

	if(as->asfd->fd<0)
	{
		logp("fd not ready in %s: %d\n", __func__, as->asfd->fd);
		return -1;
	}

	if(rbuf) doread++;

	if(wbuf && wbuf->len)
		asfd_append_all_to_write_buffer(as->asfd, wbuf);

	if(as->asfd->writebuflen && !as->asfd->write_blocked_on_read)
		dowrite++; // The write buffer is not yet empty.

	if(doread)
	{
		if(parse_readbuf(as->asfd, rbuf)) return -1;
		if(rbuf->buf) return 0;

		if(as->asfd->read_blocked_on_write) doread=0;
	}

        if(doread || dowrite)
        {
                mfd=-1;

                if(doread) FD_ZERO(&fsr);
                if(dowrite) FD_ZERO(&fsw);
                FD_ZERO(&fse);

                add_fd_to_sets(as->asfd->fd,
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

		if(!FD_ISSET(as->asfd->fd, &fse)
		  && (!doread || !FD_ISSET(as->asfd->fd, &fsr))
		  && (!dowrite || !FD_ISSET(as->asfd->fd, &fsw)))
		{
			// Be careful to avoid 'read quick' mode.
			if((as->setsec || as->setusec)
			  && as->asfd->max_network_timeout>0
			  && as->asfd->network_timeout--<=0)
			{
				logp("No activity on network for %d seconds.\n",
					as->asfd->max_network_timeout);
				return -1;
			}
			return 0;
		}
		as->asfd->network_timeout=as->asfd->max_network_timeout;

                if(FD_ISSET(as->asfd->fd, &fse))
                {
                        logp("error on socket\n");
                        return -1;
                }

                if(doread && FD_ISSET(as->asfd->fd, &fsr)) // able to read
                {
			if(as->asfd->ssl)
			{
				as->asfd->read_blocked_on_write=0;
				if(do_read_ssl(as->asfd)) return -1;
			}
			else
			{
				if(do_read(as->asfd)) return -1;
			}
			return parse_readbuf(as->asfd, rbuf);
                }

                if(dowrite && FD_ISSET(as->asfd->fd, &fsw)) // able to write
		{
			if(as->asfd->ssl)
			{
				as->asfd->write_blocked_on_read=0;
				return do_write_ssl(as->asfd);
			}
			else
				return do_write(as->asfd);
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

static int asfd_init(struct asfd *asfd, int afd, SSL *assl, struct conf *conf)
{
	asfd->fd=afd;
	asfd->ssl=assl;
	asfd->max_network_timeout=conf->network_timeout;
	asfd->network_timeout=asfd->max_network_timeout;
	asfd->ratelimit=conf->ratelimit;
	asfd->rlsleeptime=10000;

	asfd->append_all_to_write_buffer=asfd_append_all_to_write_buffer;
	asfd->set_bulk_packets=asfd_set_bulk_packets;

	if(async_alloc_buf(&asfd->readbuf, &asfd->readbuflen)
	  || async_alloc_buf(&asfd->writebuf, &asfd->writebuflen))
		return -1;
	return 0;
}

static struct asfd *asfd_alloc(void)
{
	struct asfd *asfd;
	if(!(asfd=(struct asfd *)calloc(1, sizeof(struct asfd))))
		log_out_of_memory(__func__);
	else
		asfd->init=asfd_init;
	return asfd;
}

static int async_init(struct async *as,
	int afd, SSL *assl, struct conf *conf, int estimate)
{
	if(!(as->asfd=asfd_alloc())) return -1;

	if(as->asfd->init(as->asfd, afd, assl, conf)) return -1;

	as->setsec=1;
	as->setusec=0;
	as->doing_estimate=estimate;

	as->rw=async_rw;
	as->read=async_read;
	as->write=async_write;
	as->read_quick=async_read_quick;

	as->write_strn=async_write_strn;
	as->write_str=async_write_str;
	as->read_expect=async_read_expect;
	as->simple_loop=async_simple_loop;
	as->settimers=async_settimers;

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
