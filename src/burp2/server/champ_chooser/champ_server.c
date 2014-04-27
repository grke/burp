#include "include.h"

#include <sys/un.h>

typedef struct clifd clifd_t;

struct clifd
{
	int fd;
	char *cname;
	struct incoming *in;

	char *readbuf;
	size_t readbuflen;
	struct iobuf *rbuf;

	char *writebuf;
	size_t writebuflen;
	struct iobuf *wbuf;

	struct clifd *next;
};

// FIX THIS (somehow): duplicating a lot of stuff from async.c.
// The trouble is that async.c only deals with a single fd to read/write.
// This stuff has multiple fds, including one that is listening for new
// connections.
static size_t bufmaxsize=(ASYNC_BUF_LEN*2)+32;

static void truncate_buf(char **buf, size_t *buflen)
{
	(*buf)[0]='\0';
	*buflen=0;
}

static int parse_readbuf(struct clifd *c, struct iobuf *rbuf)
{
	unsigned int s=0;
	char cmdtmp='\0';

	if(c->readbuflen>=5)
	{
		if((sscanf(c->readbuf, "%c%04X", &cmdtmp, &s))!=2)
		{
			logp("sscanf of '%s' failed in %s\n",
				c->readbuf, __func__);
			truncate_buf(&c->readbuf, &c->readbuflen);
			return -1;
		}
	}
	if(c->readbuflen>=s+5)
	{
		rbuf->cmd=cmdtmp;
		if(!(rbuf->buf=(char *)malloc(s+1)))
		{
			log_out_of_memory(__func__);
			truncate_buf(&c->readbuf, &c->readbuflen);
			return -1;
		}
		if(!(memcpy(rbuf->buf, c->readbuf+5, s)))
		{
			logp("memcpy failed in %s\n", __func__);
			truncate_buf(&c->readbuf, &c->readbuflen);
			return -1;
		}
		rbuf->buf[s]='\0';
		if(!(memmove(c->readbuf, c->readbuf+s+5, c->readbuflen-s-5)))
		{
			logp("memmove failed in %s\n", __func__);
			truncate_buf(&c->readbuf, &c->readbuflen);
			return -1;
		}
		c->readbuflen-=s+5;
		rbuf->len=s;
	}
	return 0;
}

static int clifd_alloc_buf(char **buf, size_t *buflen)
{
	if(!*buf && !(*buf=(char *)malloc(bufmaxsize)))
	{
		log_out_of_memory(__func__);
		return -1;
	}
	truncate_buf(buf, buflen);
	return 0;
}

static void clifd_free(struct clifd *c)
{
	if(!c) return;
	close_fd(&c->fd);
	if(c->readbuf) free(c->readbuf);
	if(c->writebuf) free(c->writebuf);
	iobuf_free(c->rbuf);
	iobuf_free(c->wbuf);
	// FIX THIS: free incoming?
	free(c);
}

static int append_to_write_buffer(struct clifd *c,
	const char *buf, size_t len)
{
	memcpy(c->writebuf+c->writebuflen, buf, len);
	c->writebuflen+=len;
	c->writebuf[c->writebuflen]='\0';
	return 0;
}

static int append_all_to_write_buffer(struct clifd *c,
	struct iobuf *wbuf)
{
	size_t sblen=0;
	char sbuf[10]="";
	if(c->writebuflen+6+(wbuf->len) >= bufmaxsize-1)
		return 1;

	snprintf(sbuf, sizeof(sbuf), "%c%04X",
		wbuf->cmd, (unsigned int)wbuf->len);
	sblen=strlen(sbuf);
	append_to_write_buffer(c, sbuf, sblen);
	append_to_write_buffer(c, wbuf->buf, wbuf->len);
	wbuf->len=0;
	return 0;
}

static int champ_chooser_incoming_client(int s, struct clifd **clifds)
{
	socklen_t t;
	struct clifd *newfd=NULL;
	struct sockaddr_un remote;

	if(!(newfd=(struct clifd *)calloc(1, sizeof(struct clifd)))
	  || !(newfd->cname=strdup("(unknown)")))
	{
		log_out_of_memory(__func__);
		goto error;
	}
	if(clifd_alloc_buf(&newfd->readbuf, &newfd->readbuflen)
	  || clifd_alloc_buf(&newfd->writebuf, &newfd->writebuflen)
	  || !(newfd->rbuf=iobuf_alloc())
	  || !(newfd->wbuf=iobuf_alloc()))
		goto error;

	t=sizeof(remote);
	if((newfd->fd=accept(s, (struct sockaddr *)&remote, &t))<0)
	{
		logp("accept error in %s: %s\n",
			__func__, strerror(errno));
		goto error;
	}
	set_non_blocking(newfd->fd);
	newfd->next=*clifds;
	*clifds=newfd;

	logp("Connected to fd %d\n", newfd->fd);

	return 0;
error:
	clifd_free(newfd);
	return -1;
}

static void remove_clifd(struct clifd **clifds, struct clifd *c)
{
	struct clifd *l;
	if(*clifds==c)
	{
		*clifds=c->next;
		return;
	}
	for(l=*clifds; l; l=l->next)
	{
		if(l->next!=c) continue;
		l->next=c->next;
		break;
	}
	return;
}

static int do_read(struct clifd *c)
{
	ssize_t r;
	r=read(c->fd, c->readbuf+c->readbuflen, bufmaxsize-c->readbuflen);
	if(r<0)
	{
		if(errno==EAGAIN || errno==EINTR)
			return 0;
		logp("read problem in %s\n", __func__);
		truncate_buf(&c->readbuf, &c->readbuflen);
		return -1;
	}
	else if(!r)
	{
		// End of data.
		logp("end of data in %s\n", __func__);
		truncate_buf(&c->readbuf, &c->readbuflen);
		return -1;
	}
	c->readbuflen+=r;
	c->readbuf[c->readbuflen]='\0';
	return 0;
}

static int do_write(struct clifd *c)
{
	ssize_t w;
	//if(c->ratelimit && check_ratelimit(c)) return 0;

	w=write(c->fd, c->writebuf, c->writebuflen);
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
	//if(c->ratelimit) c->rlbytes+=w;
	memmove(c->writebuf, c->writebuf+w, c->writebuflen-w);
	c->writebuflen-=w;
	return 0;
}

static int champ_loop(int s, struct clifd **clifds,
	int *started, struct conf *conf)
{
	int mfd=-1;
	fd_set fsr;
	fd_set fsw;
	fd_set fse;
	struct clifd *c;
	struct timeval tval;
	//char buf[256]="";
	//size_t sz;
	int dowrite=0;

	for(c=*clifds; c; c=c->next)
	{
		if(parse_readbuf(c, c->rbuf)) return -1;
		if(c->rbuf->buf) return 0;
		if(c->writebuflen) dowrite=1;
	}

	FD_ZERO(&fsr);
	FD_ZERO(&fsw);
	FD_ZERO(&fse);

	tval.tv_sec=1;
	tval.tv_usec=0;

	add_fd_to_sets(s, &fsr, NULL, &fse, &mfd);
	for(c=*clifds; c; c=c->next)
		add_fd_to_sets(c->fd, &fsr,
			c->writebuflen?&fsw:NULL, &fse, &mfd);

	if(select(mfd+1, &fsr, dowrite?&fsw:NULL, &fse, &tval)<0)
	{
		if(errno!=EAGAIN && errno!=EINTR)
		{
			logp("select error in normal part of %s: %s\n",
				__func__, strerror(errno));
			goto error;
		}
	}

	// Check clifds first, as adding an incoming client below will add
	// another clifd to the list.
	for(c=*clifds; c; c=c->next)
	{
		if(FD_ISSET(c->fd, &fse))
		{
			remove_clifd(clifds, c);
			logp("%d had an exception\n", c->fd);
			clifd_free(c);
			break;
		}
		if(FD_ISSET(c->fd, &fsr))
		{
			if(do_read(c))
			{
				remove_clifd(clifds, c);
				logp("%d has disconnected after do_read\n",
					c->fd);
				clifd_free(c);
			}
		}
		if(c->writebuflen && FD_ISSET(c->fd, &fsw))
		{
			if(do_write(c))
			{
				remove_clifd(clifds, c);
				logp("%d has disconnected after do_write\n",
					c->fd);
				clifd_free(c);
			}
		}
	}

	if(FD_ISSET(s, &fse))
	{
		logp("main champ chooser server socket had an exception\n");
		goto error;
	}

	if(FD_ISSET(s, &fsr))
	{
		// Incoming client.
		if(champ_chooser_incoming_client(s, clifds))
			goto error;
		*started=1;
	}

	return 0;
error:
	return -1;
}

static int deal_with_client_rbuf(struct clifd *c)
{
	if(c->rbuf->cmd==CMD_GEN)
	{
		if(!strncmp_w(c->rbuf->buf, "cname:"))
		{
			struct iobuf wbuf;
			if(c->cname) free(c->cname);
			if(!(c->cname=strdup(c->rbuf->buf+strlen("cname:"))))
			{
				log_out_of_memory(__func__);
				return -1;
			}
			logp("%d has name: %s\n", c->fd, c->cname);
			iobuf_set(&wbuf, CMD_GEN,
				(char *)"cname ok", strlen("cname ok"));
			if(append_all_to_write_buffer(c, &wbuf))
				return -1;
		}
		else
		{
			iobuf_log_unexpected(c->rbuf, __func__);
			return -1;
		}
	}
	else
	{
		printf("Got read from %d: %s\n", c->fd, c->rbuf->buf);
	}
	iobuf_free_content(c->rbuf);
	return 0;
}

int champ_chooser_server(struct sdirs *sdirs, struct conf *conf)
{
	int s;
	int ret=-1;
	int len;
	struct clifd *c=NULL;
	struct clifd *clifds=NULL;
	struct sockaddr_un local;
	struct lock *lock=NULL;
	int started=0;

	if(!(lock=lock_alloc_and_init(sdirs->champlock)))
		goto end;
	lock_get(lock);
	switch(lock->status)
	{
		case GET_LOCK_GOT:
			set_logfp(sdirs->champlog, conf);
			logp("Got champ lock for dedup_group: %s\n",
				conf->dedup_group);
			break;
		case GET_LOCK_NOT_GOT:
		case GET_LOCK_ERROR:
		default:
			//logp("Did not get champ lock\n");
			goto end;
	}

	unlink(local.sun_path);
	if((s=socket(AF_UNIX, SOCK_STREAM, 0))<0)
	{
		logp("socket error in %s: %s\n", __func__, strerror(errno));
		goto end;
	}

	memset(&local, 0, sizeof(struct sockaddr_un));
	local.sun_family=AF_UNIX;
	strcpy(local.sun_path, sdirs->champsock);
	len=strlen(local.sun_path)+sizeof(local.sun_family);
	if(bind(s, (struct sockaddr *)&local, len)<0)
	{
		logp("bind error in %s: %s\n", __func__, strerror(errno));
		goto end;
	}

	if(listen(s, 5)<0)
	{
		logp("listen error in %s: %s\n", __func__, strerror(errno));
		goto end;
	}
	set_non_blocking(s);

	// Load the sparse indexes for this dedup group.
	if(champ_chooser_init(sdirs->data, conf))
		goto end;

	while(!champ_loop(s, &clifds, &started, conf))
	{
		for(c=clifds; c; c=c->next)
		{
			while(1)
			{
				if(parse_readbuf(c, c->rbuf)) goto end;
				if(!c->rbuf->buf) break;
				if(deal_with_client_rbuf(c)) goto end;
			}
		}
		if(started && !clifds)
		{
			logp("All clients disconnected.\n");
			ret=0;
			break;
		}
	}

end:
	logp("champ chooser exiting: %d\n", ret);
	set_logfp(NULL, conf);
	close_fd(&s);
	unlink(sdirs->champsock);
// FIX THIS: free clisocks.
	lock_release(lock);
	lock_free(&lock);
	return ret;
}
