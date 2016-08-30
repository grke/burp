#include "burp.h"
#include "alloc.h"
#include "asfd.h"
#include "async.h"
#include "cmd.h"
#include "iobuf.h"
#include "prepend.h"
#include "incexc_recv.h"

static const char *endreqstrf;
static const char *endrepstrf;

static int add_to_incexc(char **incexc, const char *src, size_t len)
{
	char *tmp;
	if(!(tmp=prepend_n(*incexc?:"", src, len, *incexc?"\n":""))) return -1;
	free_w(incexc);
	*incexc=tmp;
	return 0;
}

static enum asl_ret incexc_recv_func(struct asfd *asfd,
        __attribute__ ((unused)) struct conf **confs, void *param)
{
	char **incexc=(char **)param;
	if(!strcmp(asfd->rbuf->buf, endreqstrf))
	{
		if(asfd->write_str(asfd, CMD_GEN, endrepstrf))
			return ASL_END_ERROR;
		return ASL_END_OK;
	}
	if(add_to_incexc(incexc,
		asfd->rbuf->buf, asfd->rbuf->len))
			return ASL_END_ERROR;
	return ASL_CONTINUE;
}


static int incexc_recv(struct asfd *asfd, char **incexc,
	const char *repstr, const char *endreqstr,
	const char *endrepstr, struct conf **confs)
{
	free_w(incexc);
	if(asfd->write_str(asfd, CMD_GEN, repstr)) return -1;

	endreqstrf=endreqstr;
	endrepstrf=endrepstr;
	if(asfd->simple_loop(asfd, confs, incexc, __func__, incexc_recv_func))
		return -1;

	// Need to put another new line at the end.
	return add_to_incexc(incexc, "\n", 1);
}

int incexc_recv_client(struct asfd *asfd,
	char **incexc, struct conf **confs)
{
	return incexc_recv(asfd, incexc,
		"sincexc ok", "sincexc end", "sincexc end ok",
		confs);
}

int incexc_recv_client_restore(struct asfd *asfd,
	char **incexc, struct conf **confs)
{
	return incexc_recv(asfd, incexc,
		"srestore ok", "srestore end", "srestore end ok",
		confs);
}

int incexc_recv_server(struct asfd *asfd,
	char **incexc, struct conf **confs)
{
	return incexc_recv(asfd, incexc,
		"incexc ok", "incexc end", "incexc end ok",
		confs);
}
