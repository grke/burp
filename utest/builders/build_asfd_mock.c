#include "../../src/burp.h"
#include "../../src/alloc.h"
#include "../../src/asfd.h"
#include "../../src/cmd.h"
#include "../../src/iobuf.h"
#include "build_asfd_mock.h"
#include <check.h>

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
	struct ioevent_list *reads=(struct ioevent_list *)asfd->data1;

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
	struct iobuf *expected;
	struct ioevent_list *writes=(struct ioevent_list *)asfd->data2;
	w=&writes->ioevent[writes->cursor++];
	expected=&w->iobuf;
//printf("%c %c\n", wcmd, expected->cmd);
//printf("%s %s\n", wsrc, expected->buf);
	fail_unless(wcmd==expected->cmd);
	ck_assert_str_eq(expected->buf, wsrc);
	return w->ret;
}

static enum append_ret mock_asfd_append_all_to_write_buffer(struct asfd *asfd,
	struct iobuf *wbuf)
{
	enum append_ret ret;
	ret=(enum append_ret)mock_asfd_write_str(asfd, wbuf->cmd, wbuf->buf);
	wbuf->len=0;
	return ret;
}

static int mock_parse_readbuf(struct asfd *asfd)
{
	return 0;
}

struct asfd *asfd_mock_setup(struct ioevent_list *user_reads,
	struct ioevent_list *user_writes,
	unsigned int r_size,
	unsigned int w_size)
{
	struct asfd *asfd=NULL;
	fail_unless((asfd=asfd_alloc())!=NULL);
	fail_unless((asfd->rbuf=iobuf_alloc())!=NULL);
	asfd->read=mock_asfd_read;
	asfd->read_expect=mock_asfd_read_expect;
	asfd->write_str=mock_asfd_write_str;
	asfd->append_all_to_write_buffer=mock_asfd_append_all_to_write_buffer;
	asfd->parse_readbuf=mock_parse_readbuf;
	ioevent_list_init(user_reads, r_size);
	ioevent_list_init(user_writes, w_size);
	asfd->data1=(void *)user_reads;
	asfd->data2=(void *)user_writes;
	return asfd;
};

void asfd_mock_teardown(struct ioevent_list *user_reads,
	struct ioevent_list *user_writes)
{
	free_v((void **)&user_reads->ioevent);
	free_v((void **)&user_writes->ioevent);
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

void asfd_mock_read(struct asfd *asfd,
	int *r, int ret, enum cmd cmd, const char *str)
{
	struct ioevent_list *reads=(struct ioevent_list *)asfd->data1;
	add_to_ioevent(reads->ioevent, r, ret, cmd, str, 1 /* dup */);
}

void asfd_mock_write(struct asfd *asfd,
	int *w, int ret, enum cmd cmd, const char *str)
{
	struct ioevent_list *writes=(struct ioevent_list *)asfd->data2;
	add_to_ioevent(writes->ioevent, w, ret, cmd, str, 0 /* no dup */);
}
