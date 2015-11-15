#include "../test.h"
#include "../../src/alloc.h"
#include "../../src/protocol1/rs_buf.h"

static rs_filebuf_t *setup(rs_buffers_t *rsbuf, int data_len)
{
	rs_filebuf_t *fb;
        if(rsbuf) memset(rsbuf, 0, sizeof(rs_buffers_t));
	fail_unless((fb=rs_filebuf_new(
		NULL, // asfd
		NULL, // bfd
		NULL, // fzp
		-1,   // fd
		32,   // buf_len
		data_len,
		NULL  // cntr
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

START_TEST(test_protocol1_rs_buf)
{
	do_init_test(0);
	do_init_test(1);
}
END_TEST

START_TEST(test_protocol1_rs_infilebuf_fill)
{
	rs_buffers_t rsbuf;
	rs_filebuf_t *fb;
	fb=setup(&rsbuf, 0 /*data_len*/);
	fail_unless(rs_infilebuf_fill(NULL /*job*/, &rsbuf, fb)==RS_DONE);
	tear_down(&fb);
}
END_TEST

START_TEST(test_protocol1_rs_infilebuf_fill_error1)
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

Suite *suite_protocol1_rs_buf(void)
{
	Suite *s;
	TCase *tc_core;

	s=suite_create("protocol1_rs_buf");

	tc_core=tcase_create("Core");

	tcase_add_test(tc_core, test_protocol1_rs_buf);
	tcase_add_test(tc_core, test_protocol1_rs_infilebuf_fill);
	tcase_add_test(tc_core, test_protocol1_rs_infilebuf_fill_error1);
	suite_add_tcase(s, tc_core);

	return s;
}
