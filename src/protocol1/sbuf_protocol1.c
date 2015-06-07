#include "../cmd.h"
#include "sbuf_protocol1.h"

struct protocol1 *sbuf_protocol1_alloc(void)
{
	return (struct protocol1 *)calloc_w(1,
		sizeof(struct protocol1), __func__);
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
	iobuf_free_content(&protocol1->datapth);
	iobuf_free_content(&protocol1->endfile);
	protocol1->datapth.cmd=CMD_DATAPTH;
	protocol1->endfile.cmd=CMD_END_FILE;
}
