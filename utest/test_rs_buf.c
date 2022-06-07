#include "test.h"
#include "../src/alloc.h"
#include "../src/rs_buf.h"

static rs_filebuf_t *setup(rs_buffers_t *rsbuf, int data_len)
{
	rs_filebuf_t *fb;
	alloc_check_init();
        if(rsbuf) memset(rsbuf, 0, sizeof(rs_buffers_t));
	fail_unless((fb=rs_filebuf_new(
		NULL, // bfd
		NULL, // fzp
		NULL, // asfd
		32,   // buf_len
		data_len
	))!=NULL);
	return fb;
}

static void tear_down(rs_filebuf_t **fb)
{
	rs_filebuf_free(fb);
	alloc_check();
}

static void do_init_test(int data_len)
{
	rs_filebuf_t *fb;
	fb=setup(NULL, data_len);
	fail_unless(fb->do_known_byte_count==data_len);
	tear_down(&fb);
}

START_TEST(test_rs_buf)
{
	do_init_test(0);
	do_init_test(1);
}
END_TEST

START_TEST(test_rs_buf_alloc_failure)
{
	rs_filebuf_t *fb;
	alloc_errors=1;
	fail_unless((fb=rs_filebuf_new(
		NULL, // bfd
		NULL, // fzp
		NULL, // asfd
		32,   // buf_len
		20    // data_len
	))==NULL);
}
END_TEST

START_TEST(test_rs_infilebuf_fill)
{
	rs_buffers_t rsbuf;
	rs_filebuf_t *fb;
	fb=setup(&rsbuf, 0 /*data_len*/);
	fail_unless(rs_infilebuf_fill(NULL /*job*/, &rsbuf, fb)==RS_DONE);
	tear_down(&fb);
}
END_TEST

START_TEST(test_rs_infilebuf_fill_error1)
{
	char *next_in=(char *)"next_in";
	rs_buffers_t rsbuf;
	rs_filebuf_t *fb;
	fb=setup(&rsbuf, 0 /*data_len*/);
	rsbuf.next_in=next_in;
	rsbuf.avail_in=64; // greater than fb->buf_len
	fail_unless(rs_infilebuf_fill(NULL /*job*/, &rsbuf, fb)==RS_IO_ERROR);
	tear_down(&fb);
}
END_TEST

START_TEST(test_rs_infilebuf_fill_error2)
{
	rs_buffers_t rsbuf;
	rs_filebuf_t *fb;
	fb=setup(&rsbuf, 0 /*data_len*/);
	rsbuf.next_in=fb->buf-1; // buf->next_in < fb->buf
	rsbuf.avail_in=1;
	fail_unless(rs_infilebuf_fill(NULL /*job*/, &rsbuf, fb)==RS_IO_ERROR);
	tear_down(&fb);
}
END_TEST

START_TEST(test_rs_infilebuf_fill_error3)
{
	rs_buffers_t rsbuf;
	rs_filebuf_t *fb;
	fb=setup(&rsbuf, 0 /*data_len*/);
	// buf->next_in > fb->buf + fb->buf_len
	rsbuf.next_in=fb->buf+fb->buf_len+1;
	fail_unless(rs_infilebuf_fill(NULL /*job*/, &rsbuf, fb)==RS_IO_ERROR);
	tear_down(&fb);
}
END_TEST

START_TEST(test_rs_infilebuf_fill_error4)
{
	rs_buffers_t rsbuf;
	rs_filebuf_t *fb;
	fb=setup(&rsbuf, 0 /*data_len*/);
	// !buf->next_in && buf->avail_in
	rsbuf.next_in=NULL;
	rsbuf.avail_in=1;
	fail_unless(rs_infilebuf_fill(NULL /*job*/, &rsbuf, fb)==RS_IO_ERROR);
	tear_down(&fb);
}
END_TEST

START_TEST(test_rs_infilebuf_fill_eof)
{
	rs_buffers_t rsbuf;
	rs_filebuf_t *fb;
	fb=setup(&rsbuf, 0 /*data_len*/);
	rsbuf.eof_in=1;
	fail_unless(rs_infilebuf_fill(NULL /*job*/, &rsbuf, fb)==RS_DONE);
	tear_down(&fb);
}
END_TEST

START_TEST(test_rs_outfilebuf_drain)
{
	rs_buffers_t rsbuf;
	rs_filebuf_t *fb;
	fb=setup(&rsbuf, 0 /*data_len*/);
	fail_unless(rs_outfilebuf_drain(NULL /*job*/, &rsbuf, fb)==RS_DONE);
	tear_down(&fb);
}
END_TEST

START_TEST(test_rs_outfilebuf_drain_error1)
{
	char *next_out=(char *)"next_out";
	rs_buffers_t rsbuf;
	rs_filebuf_t *fb;
	fb=setup(&rsbuf, 0 /*data_len*/);
	rsbuf.next_out=next_out;
	rsbuf.avail_out=64; // greater than fb->buf_len
	fail_unless(rs_outfilebuf_drain(NULL /*job*/, &rsbuf, fb)==RS_IO_ERROR);
	tear_down(&fb);
}
END_TEST

START_TEST(test_rs_outfilebuf_drain_error2)
{
	rs_buffers_t rsbuf;
	rs_filebuf_t *fb;
	fb=setup(&rsbuf, 0 /*data_len*/);
	rsbuf.next_out=fb->buf-1; // buf->next_out < fb->buf
	rsbuf.avail_out=1;
	fail_unless(rs_outfilebuf_drain(NULL /*job*/, &rsbuf, fb)==RS_IO_ERROR);
	tear_down(&fb);
}
END_TEST

START_TEST(test_rs_outfilebuf_drain_error3)
{
	rs_buffers_t rsbuf;
	rs_filebuf_t *fb;
	fb=setup(&rsbuf, 0 /*data_len*/);
	// buf->next_out > fb->buf + fb->buf_len
	rsbuf.next_out=fb->buf+fb->buf_len+1;
	fail_unless(rs_outfilebuf_drain(NULL /*job*/, &rsbuf, fb)==RS_IO_ERROR);
	tear_down(&fb);
}
END_TEST

START_TEST(test_rs_outfilebuf_drain_error4)
{
	rs_buffers_t rsbuf;
	rs_filebuf_t *fb;
	fb=setup(&rsbuf, 0 /*data_len*/);
	// !buf->next_out && buf->avail_out
	rsbuf.next_out=NULL;
	rsbuf.avail_out=1;
	fail_unless(rs_outfilebuf_drain(NULL /*job*/, &rsbuf, fb)==RS_IO_ERROR);
	tear_down(&fb);
}
END_TEST

Suite *suite_rs_buf(void)
{
	Suite *s;
	TCase *tc_core;

	s=suite_create("rs_buf");

	tc_core=tcase_create("Core");

	tcase_add_test(tc_core, test_rs_buf);
	tcase_add_test(tc_core, test_rs_buf_alloc_failure);

	tcase_add_test(tc_core, test_rs_infilebuf_fill);
	tcase_add_test(tc_core, test_rs_infilebuf_fill_error1);
	tcase_add_test(tc_core, test_rs_infilebuf_fill_error2);
	tcase_add_test(tc_core, test_rs_infilebuf_fill_error3);
	tcase_add_test(tc_core, test_rs_infilebuf_fill_error4);
	tcase_add_test(tc_core, test_rs_infilebuf_fill_eof);

	tcase_add_test(tc_core, test_rs_outfilebuf_drain);
	tcase_add_test(tc_core, test_rs_outfilebuf_drain_error1);
	tcase_add_test(tc_core, test_rs_outfilebuf_drain_error2);
	tcase_add_test(tc_core, test_rs_outfilebuf_drain_error3);
	tcase_add_test(tc_core, test_rs_outfilebuf_drain_error4);

	suite_add_tcase(s, tc_core);

	return s;
}
