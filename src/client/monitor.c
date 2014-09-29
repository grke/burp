#include "include.h"

static int parse_data(struct asfd *sfd, struct asfd *asfd)
{
	int ret=0;
	// Hacky to switch on whether it is using char buffering or not.
	if(asfd->streamtype==ASFD_STREAM_LINEBUF)
	{
		// Write stdin input to server.
                ret=sfd->write_strn(sfd,
			CMD_GEN, asfd->rbuf->buf, asfd->rbuf->len);
	}
	else
	{
		// Print stuff from server direct to stdout.
		fprintf(stdout, "%s", asfd->rbuf->buf);
		fflush(stdout);
	}
	iobuf_free_content(asfd->rbuf);
	return ret;
}


static int main_loop(struct async *as, struct conf *conf)
{
	struct asfd *asfd=NULL;
	struct asfd *sfd=as->asfd; // Server fd.
	while(1)
	{
		if(as->read_write(as))
		{
			logp("Exiting main loop\n");
			break;
		}

		for(asfd=as->asfd; asfd; asfd=asfd->next)
			while(asfd->rbuf->buf)
		{
			if(parse_data(sfd, asfd)) goto error;
			iobuf_free_content(asfd->rbuf);
			if(asfd->parse_readbuf(asfd))
				goto error;
		}

		//if(sel) logp("sel: %s\n", sel->name);
	}

error:
	// FIX THIS: should probably be freeing a bunch of stuff here.
	return -1;
}

// FIX THIS: Identical function in status_server.c and probably elsewhere.
static int setup_asfd(struct async *as, const char *desc, int *fd,
	enum asfd_streamtype asfd_streamtype, struct conf *conf)
{
	struct asfd *asfd=NULL;
	if(!fd || *fd<0) return 0;
	set_non_blocking(*fd);
	if(!(asfd=asfd_alloc())
	  || asfd->init(asfd, desc, as, *fd, NULL, asfd_streamtype, conf))
		goto error;
	*fd=-1;
	as->asfd_add(as, asfd);
	return 0;
error:
	asfd_free(&asfd);
	return -1;
}

int do_monitor_client(struct asfd *asfd, struct conf *conf)
{
	int ret=-1;
	struct async *as=asfd->as;
	int stdinfd=fileno(stdin);
logp("in monitor\n");
	setbuf(stdout, NULL);
	if(setup_asfd(as, "stdin", &stdinfd, ASFD_STREAM_LINEBUF, conf))
		goto end;
	ret=main_loop(as, conf);
end:
	return ret;
}
