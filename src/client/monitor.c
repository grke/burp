#include "../burp.h"
#include "../asfd.h"
#include "../async.h"
#include "../conf.h"
#include "../cmd.h"
#include "../iobuf.h"
#include "../log.h"
#include "monitor.h"

static int copy_input_to_output(struct asfd *in, struct asfd *out)
{
	struct iobuf wbuf;
	iobuf_set(&wbuf, CMD_GEN, in->rbuf->buf, in->rbuf->len);
	return out->write(out, &wbuf);
}

#ifndef UTEST
static
#endif
int monitor_client_main_loop(struct async *as)
{
	struct asfd *asfd;
	struct asfd *sfd; // Server fd.
	struct asfd *sin;
	struct asfd *sout;

	sfd=as->asfd;
	sin=sfd->next;
	sout=sin->next;

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
			if(asfd==sfd)
			{
				if(copy_input_to_output(sfd, sout))
					goto error;
			}
			else if(asfd==sin)
			{
				if(copy_input_to_output(sin, sfd))
					goto error;
			}
			iobuf_free_content(asfd->rbuf);
			if(asfd->parse_readbuf(asfd))
				goto error;
		}

		//if(sel) logp("sel: %s\n", sel->name);
	}

error:
	return -1;
}

int do_monitor_client(struct asfd *asfd)
{
	int ret=-1;
	struct async *as=asfd->as;
logp("in monitor\n");

	// I tried to just printf to stdout, but the strings to print would be
	// so long that I would start to get printf errors.
	// Using the asfd stuff works well though.
	if(!setup_asfd_stdin(as)
	 || !setup_asfd_stdout(as))
		goto end;
	ret=monitor_client_main_loop(as);
end:
	return ret;
}
