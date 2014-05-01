#include "include.h"

int clifd_alloc_buf(char **buf, size_t *buflen, size_t bufmaxlen)
{
	if(!*buf && !(*buf=(char *)malloc(bufmaxlen)))
	{
		log_out_of_memory(__func__);
		return -1;
	}
	clifd_truncate_buf(buf, buflen);
	return 0;
}

void clifd_free(struct clifd *c)
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

void clifd_remove(struct clifd **clifds, struct clifd *c)
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

void clifd_truncate_buf(char **buf, size_t *buflen)
{
	(*buf)[0]='\0';
	*buflen=0;
}
