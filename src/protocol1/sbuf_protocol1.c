#include "../burp.h"
#include "sbuf_protocol1.h"
#include "../alloc.h"
#include "../cmd.h"

static void sbuf_protocol1_init(struct protocol1 *protocol1)
{
	iobuf_free_content(&protocol1->datapth);
	protocol1->datapth.cmd=CMD_DATAPTH;
}

struct protocol1 *sbuf_protocol1_alloc(void)
{
	struct protocol1 *p;
	if((p=(struct protocol1 *)calloc_w(1,
		sizeof(struct protocol1), __func__)))
			sbuf_protocol1_init(p);
	return p;
}

void sbuf_protocol1_free_content(struct protocol1 *protocol1)
{
	if(!protocol1) return;
	memset(&(protocol1->rsbuf), 0, sizeof(protocol1->rsbuf));
	if(protocol1->sigjob)
		{ rs_job_free(protocol1->sigjob); protocol1->sigjob=NULL; }
	rs_filebuf_free(&protocol1->infb);
	rs_filebuf_free(&protocol1->outfb);
	fzp_close(&protocol1->sigfzp);
	fzp_close(&protocol1->fzp);
	protocol1->salt=0;
	sbuf_protocol1_init(protocol1);
}
