#include "../../src/burp.h"
#include "../../src/alloc.h"
#include "../../src/asfd.h"
#include "../../src/cmd.h"
#include "../../src/iobuf.h"
#include "build_asfd_mock.h"
#include <check.h>

static void ioevent_list_init(struct ioevent_list *list)
{
	memset(list, 0, sizeof(*list));
}

static void ioevent_list_grow(struct ioevent_list *list)
{
	list->size++;
	list->ioevent=(struct ioevent *)
		realloc_w(list->ioevent,
			list->size*sizeof(struct ioevent), __func__);
	fail_unless(list->ioevent!=NULL);
}

static int mock_asfd_read(struct asfd *asfd)
{
	struct ioevent *r;
	struct ioevent_list *reads=(struct ioevent_list *)asfd->data1;

//printf("r %s %d %d\n", asfd->desc, reads->cursor, reads->size);
	fail_unless(reads->cursor<reads->size);

	r=&reads->ioevent[reads->cursor];
	if(r->no_op)
	{
		r->no_op--;
		if(!r->no_op)
			reads->cursor++;
		return r->ret;
	}
//printf("r %s - %c:%s\n", asfd->desc, r->iobuf.cmd, r->iobuf.buf);
	iobuf_move(asfd->rbuf, &r->iobuf);
	reads->cursor++;
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
//printf("w %s %d %d\n", asfd->desc, writes->cursor, writes->size);
	fail_unless(writes->cursor<writes->size);
	w=&writes->ioevent[writes->cursor++];
	expected=&w->iobuf;
//printf("w %s - %c:%s %c:%s\n", asfd->desc, wcmd, wsrc, expected->cmd, expected->buf);
	fail_unless(wcmd==expected->cmd);
	ck_assert_str_eq(expected->buf, wsrc);
	return w->ret;
}

static int mock_asfd_write(struct asfd *asfd, struct iobuf *wbuf)
{
	return mock_asfd_write_str(asfd, wbuf->cmd, wbuf->buf);
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
	struct ioevent_list *user_writes)
{
	struct asfd *asfd=NULL;
	fail_unless((asfd=asfd_alloc())!=NULL);
	fail_unless((asfd->rbuf=iobuf_alloc())!=NULL);
	asfd->read=mock_asfd_read;
	asfd->read_expect=mock_asfd_read_expect;
	asfd->write=mock_asfd_write;
	asfd->write_str=mock_asfd_write_str;
	asfd->append_all_to_write_buffer=mock_asfd_append_all_to_write_buffer;
	asfd->parse_readbuf=mock_parse_readbuf;
	ioevent_list_init(user_reads);
	ioevent_list_init(user_writes);
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

static void add_to_ioevent(struct ioevent_list *ioevent_list,
	int *i, int ret, enum cmd cmd, void *data, int dlen, int dup)
{
	struct ioevent *ioevent;
	ioevent_list_grow(ioevent_list);
	ioevent=ioevent_list->ioevent;
	ioevent[*i].ret=ret;
	ioevent[*i].no_op=0;
	ioevent[*i].iobuf.cmd=cmd;
	ioevent[*i].iobuf.len=dlen;
	ioevent[*i].iobuf.buf=NULL;
	if(dlen)
	{
		if(dup)
		{
			fail_unless((ioevent[*i].iobuf.buf=
				(char *)malloc_w(dlen+1, __func__))!=NULL);
			fail_unless(memcpy(ioevent[*i].iobuf.buf,
				data, dlen+1)!=NULL);
		}
		else
			ioevent[*i].iobuf.buf=(char *)data;
	}
	(*i)++;
}

static void add_no_op(struct ioevent_list *ioevent_list, int *i, int count)
{
	struct ioevent *ioevent;
	ioevent_list_grow(ioevent_list);
	ioevent=ioevent_list->ioevent;
	ioevent[*i].ret=0;
	ioevent[*i].no_op=count;
	(*i)++;
}

void asfd_mock_read(struct asfd *asfd,
	int *r, int ret, enum cmd cmd, const char *str)
{
	struct ioevent_list *reads=(struct ioevent_list *)asfd->data1;
	add_to_ioevent(reads, r, ret, cmd,
		(void *)str, str?strlen(str):0,
		1 /* dup */);
}

void asfd_mock_write(struct asfd *asfd,
	int *w, int ret, enum cmd cmd, const char *str)
{
	struct ioevent_list *writes=(struct ioevent_list *)asfd->data2;
	add_to_ioevent(writes, w, ret, cmd,
		(void *)str, str?strlen(str):0,
		0 /* no dup */);
}

void asfd_mock_read_no_op(struct asfd *asfd, int *r, int count)
{
	struct ioevent_list *reads=(struct ioevent_list *)asfd->data1;
	add_no_op(reads, r, count);
}

void asfd_mock_read_iobuf(struct asfd *asfd,
	int *r, int ret, struct iobuf *iobuf)
{
	struct ioevent_list *reads=(struct ioevent_list *)asfd->data1;
	add_to_ioevent(reads, r, ret,
		iobuf->cmd, iobuf->buf, iobuf->len,
		1 /* dup */);
}

void asfd_mock_write_iobuf(struct asfd *asfd,
	int *w, int ret, struct iobuf *iobuf)
{
	struct ioevent_list *writes=(struct ioevent_list *)asfd->data2;
	add_to_ioevent(writes, w, ret,
		iobuf->cmd, iobuf->buf, iobuf->len,
		0 /* no dup */);
}
