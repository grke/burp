#include "include.h"

void sbuf_burp1_free_content(struct burp1 *burp1)
{
	memset(&(burp1->rsbuf), 0, sizeof(burp1->rsbuf));
	if(burp1->sigjob) { rs_job_free(burp1->sigjob); burp1->sigjob=NULL; }
	if(burp1->infb) { rs_filebuf_free(burp1->infb); burp1->infb=NULL; }
	if(burp1->outfb) { rs_filebuf_free(burp1->outfb); burp1->outfb=NULL; }
	close_fp(&burp1->sigfp); burp1->sigfp=NULL;
	gzclose_fp(&burp1->sigzp); burp1->sigzp=NULL;
	close_fp(&burp1->fp); burp1->fp=NULL;
	gzclose_fp(&burp1->zp); burp1->zp=NULL;
	iobuf_free_content(&burp1->datapth);
	iobuf_free_content(&burp1->endfile);
	burp1->datapth.cmd=CMD_DATAPTH;
	burp1->endfile.cmd=CMD_END_FILE;
}
