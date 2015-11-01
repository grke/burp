#include "../test.h"
#include "../../src/alloc.h"
#include "../../src/asfd.h"
#include "../../src/server/list.h"
#include "../../src/iobuf.h"
#include "../builders/build_asfd_mock.h"

static struct ioevent_list reads;
static struct ioevent_list writes;

static void tear_down(struct asfd **asfd)
{
	asfd_free(asfd);
	asfd_mock_teardown(&reads, &writes);
	alloc_check();
}

static void setup_bu_failure(void)
{
}

/*
static void setup_all_ok(void)
{
	int r=0; int w=0;
	asfd_mock_write(&w, 0, CMD_GEN, "hello:" VERSION);
	asfd_mock_read (&r, 0, CMD_GEN, "whoareyou");
	asfd_mock_write(&w, 0, CMD_GEN, "testclient");
	asfd_mock_read (&r, 0, CMD_GEN, "okpassword");
	asfd_mock_write(&w, 0, CMD_GEN, "password");
	asfd_mock_read (&r, 0, CMD_GEN, "ok");
}
*/

static void run_test(int expected_ret, void setup_callback(void))
{
	struct asfd *asfd=asfd_mock_setup(&reads, &writes, 10, 10);

	setup_callback();

	fail_unless(do_list_server(asfd, NULL, NULL, PROTO_1,
		NULL, NULL, NULL));
	tear_down(&asfd);
}

START_TEST(test_server_list)
{
	run_test( -1, setup_bu_failure);
}
END_TEST

Suite *suite_server_list(void)
{
	Suite *s;
	TCase *tc_core;

	s=suite_create("server_list");

	tc_core=tcase_create("Core");

	tcase_add_test(tc_core, test_server_list);
	suite_add_tcase(s, tc_core);

	return s;
}
