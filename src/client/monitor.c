#include "../burp.h"
#include "../asfd.h"
#include "../async.h"
#include "../conf.h"
#include "../cmd.h"
#include "../iobuf.h"
#include "../log.h"

static int copy_input_to_output(struct asfd *in, struct asfd *out)
{
	struct iobuf wbuf;
	iobuf_set(&wbuf, CMD_GEN, in->rbuf->buf, in->rbuf->len);
	return out->write(out, &wbuf);
}

static int main_loop(struct async *as, struct conf **confs)
{
	struct asfd *asfd;
	struct asfd *sfd; // Server fd.
	struct asfd *sin;
	struct asfd *sout;

	sfd=as->asfd;
	sin=sfd->next;
	sout=sin->next;

	// Send a blank line to kick the server off.
	if(sfd->write_str(sfd, CMD_GEN, "\n"))
		goto error;

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
	// FIX THIS: should probably be freeing a bunch of stuff here.
	return -1;
}

int do_monitor_client(struct asfd *asfd, struct conf **confs)
{
	int ret=-1;
	struct async *as=asfd->as;
	int stdinfd=fileno(stdin);
	int stdoutfd=fileno(stdout);
logp("in monitor\n");
	// I tried to just printf to stdout, but the strings to print would be
	// so long that I would start to get printf errors.
	// Using the asfd stuff works well though.
	if(!setup_asfd(as, "stdin", &stdinfd, NULL, ASFD_STREAM_LINEBUF,
		ASFD_FD_CLIENT_MONITOR_READ, -1, confs)
	  || !setup_asfd(as, "stdout", &stdoutfd, NULL, ASFD_STREAM_LINEBUF,
		ASFD_FD_CLIENT_MONITOR_WRITE, -1, confs))
		goto end;
	ret=main_loop(as, confs);
end:
	return ret;
}
