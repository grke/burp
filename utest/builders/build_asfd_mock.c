#include "../../src/burp.h"
#include "../../src/alloc.h"
#include "../../src/asfd.h"
#include "../../src/cmd.h"
#include "../../src/iobuf.h"
#include "build_asfd_mock.h"
#include <check.h>

static struct ioevent_list *reads;
static struct ioevent_list *writes;

static void ioevent_list_init(struct ioevent_list *list, unsigned int size)
{
	list->ioevent=(struct ioevent *)
		calloc_w(size, sizeof(struct ioevent), __func__);
	fail_unless(list->ioevent!=NULL);
	list->cursor=0;
}

static int mock_asfd_read(struct asfd *asfd)
{
	struct ioevent *r;
	r=&reads->ioevent[reads->cursor++];
	iobuf_move(asfd->rbuf, &r->iobuf);
	return r->ret;
}

static int mock_asfd_read_expect(struct asfd *asfd,
	enum cmd cmd, const char *expect)
{
	int ret;
	ret=mock_asfd_read(asfd);
	fail_unless(cmd==asfd->rbuf->cmd);
	ck_assert_str_eq(expect, asfd->rbuf->buf);
	iobuf_free_content(asfd->rbuf);
	return ret;
}

static int mock_asfd_write_str(struct asfd *asfd,
	enum cmd wcmd, const char *wsrc)
{
	struct ioevent *w;
	w=&writes->ioevent[writes->cursor++];
	struct iobuf *expected;
	expected=&w->iobuf;
	fail_unless(wcmd==expected->cmd);
	ck_assert_str_eq(expected->buf, wsrc);
	return w->ret;
}

struct asfd *asfd_mock_setup(struct ioevent_list *user_reads,
	struct ioevent_list *user_writes,
	unsigned int r_size,
	unsigned int w_size)
{
	struct asfd *asfd=NULL;
	reads=user_reads;
	writes=user_writes;
	fail_unless((asfd=asfd_alloc())!=NULL);
	fail_unless((asfd->rbuf=iobuf_alloc())!=NULL);
	asfd->read=mock_asfd_read;
	asfd->read_expect=mock_asfd_read_expect;
	asfd->write_str=mock_asfd_write_str;
	ioevent_list_init(reads, r_size);
	ioevent_list_init(writes, w_size);
	return asfd;
};

void asfd_mock_teardown(struct ioevent_list *user_reads,
	struct ioevent_list *user_writes)
{
	free_v((void **)&reads->ioevent);
	free_v((void **)&writes->ioevent);
}

static void add_to_ioevent(struct ioevent *ioevent,
	int *i, int ret, enum cmd cmd, const char *str, int dup)
{
	ioevent[*i].ret=ret;
	ioevent[*i].iobuf.cmd=cmd;
	if(str)
	{
		ioevent[*i].iobuf.len=strlen(str);
		if(dup)
			fail_unless((ioevent[*i].iobuf.buf
				=strdup_w(str, __func__))!=NULL);
		else
			ioevent[*i].iobuf.buf=(char *)str;
	}
	(*i)++;
	iobuf_init(&ioevent[*i].iobuf);
	ioevent[*i].ret=-1;
}

void asfd_mock_read(int *r, int ret, enum cmd cmd, const char *str)
{
	add_to_ioevent(reads->ioevent, r, ret, cmd, str, 1 /* dup */);
}

void asfd_mock_write(int *w, int ret, enum cmd cmd, const char *str)
{
	add_to_ioevent(writes->ioevent, w, ret, cmd, str, 0 /* no dup */);
}
