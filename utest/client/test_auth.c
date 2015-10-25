#include "../test.h"
#include "../../src/alloc.h"
#include "../../src/asfd.h"
#include "../../src/cmd.h"
#include "../../src/client/auth.h"
#include "../../src/iobuf.h"

static void tear_down(struct asfd **asfd)
{
	asfd_free(asfd);
	alloc_check();
}

struct ioevent
{
	struct iobuf iobuf;
	int ret;
};

static struct ioevent reads[10];
static struct ioevent writes[10];
static unsigned int rcursor=0;
static unsigned int wcursor=0;

static int mock_asfd_read(struct asfd *asfd)
{
	struct ioevent *r=&reads[rcursor++];
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
	struct ioevent *w=&writes[wcursor++];
	struct iobuf *expected;
	expected=&w->iobuf;
	fail_unless(wcmd==expected->cmd);
	ck_assert_str_eq(expected->buf, wsrc);
	return w->ret;
}

static struct asfd *setup(void)
{
	struct asfd *asfd=NULL;
	fail_unless((asfd=asfd_alloc())!=NULL);
	fail_unless((asfd->rbuf=iobuf_alloc())!=NULL);
	asfd->read=mock_asfd_read;
	asfd->read_expect=mock_asfd_read_expect;
	asfd->write_str=mock_asfd_write_str;
	rcursor=0;
	wcursor=0;
	return asfd;
};

static void add_to_reads(int *r, int ret, enum cmd cmd, const char *str)
{
	reads[*r].ret=ret;
	reads[*r].iobuf.cmd=cmd;
	if(str)
	{
		reads[*r].iobuf.len=strlen(str);
		fail_unless(
			(reads[*r].iobuf.buf=strdup_w(str, __func__))!=NULL);
	}
	(*r)++;
	reads[*r].iobuf.len=0;
	reads[*r].iobuf.buf=NULL;
}

static void add_to_writes(int *w, int ret, enum cmd cmd, const char *str)
{
	writes[*w].ret=ret;
	writes[*w].iobuf.cmd=cmd;
	if(str)
	{
		writes[*w].iobuf.len=strlen(str);
		writes[*w].iobuf.buf=(char *)str;
	}
	(*w)++;
	writes[*w].iobuf.len=0;
	writes[*w].iobuf.buf=NULL;
}

static void setup_all_ok(void)
{
	int r=0; int w=0;
	add_to_writes(&w, 0, CMD_GEN, "hello:" VERSION);
	add_to_reads (&r, 0, CMD_GEN, "whoareyou");
	add_to_writes(&w, 0, CMD_GEN, "testclient");
	add_to_reads (&r, 0, CMD_GEN, "okpassword");
	add_to_writes(&w, 0, CMD_GEN, "password");
	add_to_reads (&r, 0, CMD_GEN, "ok");
}

static void setup_all_ok_server_version(void)
{
	int r=0; int w=0;
	add_to_writes(&w, 0, CMD_GEN, "hello:" VERSION);
	add_to_reads (&r, 0, CMD_GEN, "whoareyou:" VERSION);
	add_to_writes(&w, 0, CMD_GEN, "testclient");
	add_to_reads (&r, 0, CMD_GEN, "okpassword");
	add_to_writes(&w, 0, CMD_GEN, "password");
	add_to_reads (&r, 0, CMD_GEN, "ok");
}

static void setup_all_ok_server_version_empty(void)
{
	int r=0; int w=0;
	add_to_writes(&w, 0, CMD_GEN, "hello:" VERSION);
	add_to_reads (&r, 0, CMD_GEN, "whoareyou:");
	add_to_writes(&w, 0, CMD_GEN, "testclient");
	add_to_reads (&r, 0, CMD_GEN, "okpassword");
	add_to_writes(&w, 0, CMD_GEN, "password");
	add_to_reads (&r, 0, CMD_GEN, "ok");
}

static void setup_all_ok_version_warning(void)
{
	int r=0; int w=0;
	add_to_writes(&w, 0, CMD_GEN, "hello:" VERSION);
	add_to_reads (&r, 0, CMD_GEN, "whoareyou:" VERSION);
	add_to_writes(&w, 0, CMD_GEN, "testclient");
	add_to_reads (&r, 0, CMD_GEN, "okpassword");
	add_to_writes(&w, 0, CMD_GEN, "password");
	add_to_reads (&r, 0, CMD_WARNING, "This is a version warning");
	add_to_reads (&r, 0, CMD_GEN, "ok");
}

static void setup_all_ok_version_warning_read_error(void)
{
	int r=0; int w=0;
	add_to_writes(&w,  0, CMD_GEN, "hello:" VERSION);
	add_to_reads (&r,  0, CMD_GEN, "whoareyou:" VERSION);
	add_to_writes(&w,  0, CMD_GEN, "testclient");
	add_to_reads (&r,  0, CMD_GEN, "okpassword");
	add_to_writes(&w,  0, CMD_GEN, "password");
	add_to_reads (&r,  0, CMD_WARNING, "This is a version warning");
	add_to_reads (&r, -1, CMD_GEN, "ok");
}

static void setup_not_ok(void)
{
	int r=0; int w=0;
	add_to_writes(&w, 0, CMD_GEN, "hello:" VERSION);
	add_to_reads (&r, 0, CMD_GEN, "whoareyou");
	add_to_writes(&w, 0, CMD_GEN, "testclient");
	add_to_reads (&r, 0, CMD_GEN, "okpassword");
	add_to_writes(&w, 0, CMD_GEN, "password");
	add_to_reads (&r, 0, CMD_GEN, "notok");
}

static void setup_write_fail(void)
{
	int w=0;
	add_to_writes(&w, -1, CMD_GEN, "hello:" VERSION);
}

static void setup_read_fail(void)
{
	int r=0; int w=0;
	add_to_writes(&w,  0, CMD_GEN, "hello:" VERSION);
	add_to_reads (&r, -1, CMD_GEN, "whoareyou");
}

static void setup_read_fail_2(void)
{
	int r=0; int w=0;
	add_to_writes(&w,  0, CMD_GEN, "hello:" VERSION);
	add_to_reads (&r,  0, CMD_GEN, "whoareyou");
	add_to_writes(&w,  0, CMD_GEN, "testclient");
	add_to_reads (&r, -1, CMD_GEN, "okpassword");
}

static void run_test(int expected_ret, const char *expected_server_version,
	void setup_callback(void))
{
	struct asfd *asfd=setup();
	char *server_version=NULL;

	setup_callback();

	fail_unless(authorise_client(asfd, &server_version,
		"testclient",
		"password",
		NULL /* cntr */)==expected_ret);
	if(expected_server_version)
		ck_assert_str_eq(expected_server_version, server_version);
	else
		fail_unless(server_version==NULL);
	free_w(&server_version);
	tear_down(&asfd);
}

START_TEST(test_auth)
{
	run_test( 0, NULL,    setup_all_ok);
	run_test( 0, VERSION, setup_all_ok_server_version);
	run_test( 0, "",      setup_all_ok_server_version_empty);
	run_test( 0, VERSION, setup_all_ok_version_warning);
	run_test(-1, VERSION, setup_all_ok_version_warning_read_error);
	run_test(-1, NULL,    setup_not_ok);
	run_test(-1, NULL,    setup_write_fail);
	run_test(-1, NULL,    setup_read_fail);
	run_test(-1, NULL,    setup_read_fail_2);
}
END_TEST

Suite *suite_client_auth(void)
{
	Suite *s;
	TCase *tc_core;

	s=suite_create("client_auth");

	tc_core=tcase_create("Core");

	tcase_add_test(tc_core, test_auth);
	suite_add_tcase(s, tc_core);

	return s;
}
