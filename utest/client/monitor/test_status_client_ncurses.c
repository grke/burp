#include "../../test.h"
#include "../../../src/asfd.h"
#include "../../../src/async.h"
#include "../../../src/iobuf.h"
#include "../../../src/client/monitor/status_client_ncurses.h"
#include "../../builders/build_asfd_mock.h"

static struct ioevent_list reads;
static struct ioevent_list writes;

static struct async *setup_async(void)
{
	struct async *as;
	fail_unless((as=async_alloc())!=NULL);
	as->init(as, 0 /* estimate */);
	return as;
}

START_TEST(test_status_client_ncurses_null_as)
{
	fail_unless(!status_client_ncurses_init(ACTION_STATUS_SNAPSHOT));
	fail_unless(status_client_ncurses_main_loop(
		NULL, // as
		NULL // orig_client
	)==-1);
	alloc_check();
}
END_TEST

static int async_rw_simple(struct async *as)
{
	return as->asfd->read(as->asfd);
}

static int async_write_simple(struct async *as)
{
	return 0;
}

static void setup_simplest_json(struct asfd *asfd)
{
	int r=0; int w=0;
	asfd_assert_write(asfd, &w, 0, CMD_GEN, "c:\n");
	asfd_mock_read(asfd, &r, 0, CMD_GEN, "{}");
}

static void setup_multiline_json(struct asfd *asfd)
{
	int r=0; int w=0;
	asfd_assert_write(asfd, &w, 0, CMD_GEN, "c:\n");
	asfd_mock_read(asfd, &r, 0, CMD_GEN, "\n{\n");
	asfd_mock_read(asfd, &r, 0, CMD_GEN, "\n\n\n");
	asfd_mock_read(asfd, &r, 0, CMD_GEN, "\n}\n");
}

static void setup_bad_json(struct asfd *asfd)
{
	int r=0; int w=0;
	asfd_assert_write(asfd, &w, 0, CMD_GEN, "c:\n");
	asfd_mock_read(asfd, &r, 0, CMD_GEN, "{ adfdff }\n");
}

static void setup_read_error(struct asfd *asfd)
{
	int r=0; int w=0;
	asfd_assert_write(asfd, &w, 0, CMD_GEN, "c:\n");
	asfd_mock_read(asfd, &r, -1, CMD_GEN, "");
}

static void do_simple_test(
	const char *orig_client,
	int expected_ret,
	void setup_callback(struct asfd *asfd)
)
{
	struct asfd *asfd;
	struct async *as;

	as=setup_async();
	asfd=asfd_mock_setup(&reads, &writes);
	as->asfd_add(as, asfd);
	asfd->as=as;
	as->read_write=async_rw_simple;
	as->write=async_write_simple;
	setup_callback(asfd);

	fail_unless(!status_client_ncurses_init(ACTION_STATUS_SNAPSHOT));
	fail_unless(status_client_ncurses_main_loop(
		as,
		orig_client
	)==expected_ret);
	asfd_free(&asfd);
	asfd_mock_teardown(&reads, &writes);
	async_free(&as);

	alloc_check();
}

START_TEST(test_status_client_ncurses_simplest_json)
{
	do_simple_test(NULL, 0, setup_simplest_json);
	// FIX THIS: causes segfault.
	//do_simple_test("otherclient", 0, setup_simplest_json);
}
END_TEST

START_TEST(test_status_client_ncurses_multiline_json)
{
	do_simple_test(NULL, 0, setup_multiline_json);
}
END_TEST

START_TEST(test_status_client_ncurses_bad_json)
{
	do_simple_test(NULL, -1, setup_bad_json);
}
END_TEST

START_TEST(test_status_client_ncurses_read_error)
{
	do_simple_test(NULL, -1, setup_read_error);
}
END_TEST

Suite *suite_client_monitor_status_client_ncurses(void)
{
	Suite *s;
	TCase *tc_core;

	s=suite_create("client_monitor_status_client_ncurses");

	tc_core=tcase_create("Core");
        tcase_set_timeout(tc_core, 60);

	tcase_add_test(tc_core, test_status_client_ncurses_null_as);
	tcase_add_test(tc_core, test_status_client_ncurses_read_error);
	tcase_add_test(tc_core, test_status_client_ncurses_simplest_json);
	tcase_add_test(tc_core, test_status_client_ncurses_multiline_json);
	tcase_add_test(tc_core, test_status_client_ncurses_bad_json);

	suite_add_tcase(s, tc_core);

	return s;
}
