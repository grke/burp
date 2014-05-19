#include "include.h"

void async_free(struct async **as)
{
	if(!*as) return;
	free(*as);
	*as=NULL;
}

static void async_settimers(struct async *as, int sec, int usec)
{
	as->setsec=sec;
	as->setusec=usec;
}

static int async_io(struct async *as, int doread)
{
        int mfd=-1;
        fd_set fsr;
        fd_set fsw;
        fd_set fse;
	int dosomething=0;
        struct timeval tval;
	struct asfd *asfd;

	if(as->doing_estimate) return 0;

	FD_ZERO(&fsr);
	FD_ZERO(&fsw);
	FD_ZERO(&fse);

	tval.tv_sec=as->setsec;
	tval.tv_usec=as->setusec;

	for(asfd=as->asfd; asfd; asfd=asfd->next)
	{
		asfd->doread=doread;
		asfd->dowrite=0;

		if(doread)
		{
			if(asfd->parse_readbuf(asfd)) return -1;
			if(asfd->rbuf->buf || asfd->read_blocked_on_write)
				asfd->doread=0;
		}

		if(asfd->writebuflen && !asfd->write_blocked_on_read)
			asfd->dowrite++; // The write buffer is not yet empty.

		if(!asfd->doread && !asfd->dowrite) continue;

                add_fd_to_sets(asfd->fd, asfd->doread?&fsr:NULL,
			asfd->dowrite?&fsw:NULL, &fse, &mfd);

		dosomething++;
	}
	if(!dosomething) return 0;

	if(select(mfd+1, &fsr, &fsw, &fse, &tval)<0)
	{
		if(errno!=EAGAIN && errno!=EINTR)
		{
			logp("select error in %s: %s\n", __func__,
				strerror(errno));
			return -1;
		}
	}

	for(asfd=as->asfd; asfd; asfd=asfd->next)
	{
		if(!FD_ISSET(asfd->fd, &fse)
		  && (!asfd->doread || !FD_ISSET(asfd->fd, &fsr))
		  && (!asfd->dowrite || !FD_ISSET(asfd->fd, &fsw)))
		{
			// Be careful to avoid 'read quick' mode.
			if((as->setsec || as->setusec)
			  && asfd->max_network_timeout>0
			  && asfd->network_timeout--<=0)
			{
				logp("No activity on %s for %d seconds.\n",
					asfd->desc, asfd->max_network_timeout);
				return -1;
			}
			continue;
		}
		asfd->network_timeout=asfd->max_network_timeout;

		if(FD_ISSET(asfd->fd, &fse))
		{
			logp("error on %s\n", asfd->desc);
			return -1;
		}

		if(asfd->doread && FD_ISSET(asfd->fd, &fsr)) // Able to read.
		{
			if(asfd->ssl)
			{
				asfd->read_blocked_on_write=0;
				if(asfd->do_read_ssl(asfd)) return -1;
			}
			else
			{
				if(asfd->do_read(asfd)) return -1;
			}
			if(asfd->parse_readbuf(asfd)) return -1;
		}

		if(asfd->dowrite && FD_ISSET(asfd->fd, &fsw)) // Able to write.
		{
			if(asfd->ssl)
			{
				asfd->write_blocked_on_read=0;
				if(asfd->do_write_ssl(asfd)) return -1;
			}
			else
			{
				if(asfd->do_write(asfd)) return -1;
			}
		}
	}

        return 0;
}

static int async_read_write(struct async *as)
{
	return async_io(as, 1 /* Read too. */);
}

static int async_write(struct async *as)
{
	return async_io(as, 0 /* No read. */);
}

static int async_read_quick(struct async *as)
{
	int r;
	int savesec=as->setsec;
	int saveusec=as->setusec;
	as->setsec=0;
	as->setusec=0;
	r=as->read_write(as); // Maybe make an as->read(as) function some time.
	as->setsec=savesec;
	as->setusec=saveusec;
	return r;
}

static void async_add_asfd(struct async *as, struct asfd *asfd)
{
	struct asfd *x;
	if(!as->asfd)
	{
		as->asfd=asfd;
		return ;
	}
	// Add to the end;
	for(x=as->asfd; x->next; x=x->next) { }
	x->next=asfd;
}

static int async_init(struct async *as, int estimate)
{
	as->setsec=1;
	as->setusec=0;
	as->doing_estimate=estimate;

	as->read_write=async_read_write;
	as->write=async_write;
	as->read_quick=async_read_quick;

	as->settimers=async_settimers;
	as->add_asfd=async_add_asfd;

	return 0;
}

struct async *async_alloc(void)
{
	struct async *as;
	if(!(as=(struct async *)calloc_w(1, sizeof(struct async), __func__)))
		return NULL;
	as->init=async_init;
	return as;
}
