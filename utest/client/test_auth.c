#include "../test.h"
#include "../../src/alloc.h"
#include "../../src/asfd.h"
#include "../../src/cmd.h"
#include "../../src/client/auth.h"
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

static void setup_all_ok(struct asfd *asfd)
{
	int r=0; int w=0;
	asfd_assert_write(asfd, &w, 0, CMD_GEN, "hello:" PACKAGE_VERSION);
	asfd_mock_read(asfd, &r, 0, CMD_GEN, "whoareyou");
	asfd_assert_write(asfd, &w, 0, CMD_GEN, "testclient");
	asfd_mock_read(asfd, &r, 0, CMD_GEN, "okpassword");
	asfd_assert_write(asfd, &w, 0, CMD_GEN, "password");
	asfd_mock_read(asfd, &r, 0, CMD_GEN, "ok");
}

static void setup_all_ok_server_version(struct asfd *asfd)
{
	int r=0; int w=0;
	asfd_assert_write(asfd, &w, 0, CMD_GEN, "hello:" PACKAGE_VERSION);
	asfd_mock_read(asfd, &r, 0, CMD_GEN, "whoareyou:" PACKAGE_VERSION);
	asfd_assert_write(asfd, &w, 0, CMD_GEN, "testclient");
	asfd_mock_read(asfd, &r, 0, CMD_GEN, "okpassword");
	asfd_assert_write(asfd, &w, 0, CMD_GEN, "password");
	asfd_mock_read(asfd, &r, 0, CMD_GEN, "ok");
}

static void setup_all_ok_server_version_empty(struct asfd *asfd)
{
	int r=0; int w=0;
	asfd_assert_write(asfd, &w, 0, CMD_GEN, "hello:" PACKAGE_VERSION);
	asfd_mock_read(asfd, &r, 0, CMD_GEN, "whoareyou:");
	asfd_assert_write(asfd, &w, 0, CMD_GEN, "testclient");
	asfd_mock_read(asfd, &r, 0, CMD_GEN, "okpassword");
	asfd_assert_write(asfd, &w, 0, CMD_GEN, "password");
	asfd_mock_read(asfd, &r, 0, CMD_GEN, "ok");
}

static void setup_all_ok_version_warning(struct asfd *asfd)
{
	int r=0; int w=0;
	asfd_assert_write(asfd, &w, 0, CMD_GEN, "hello:" PACKAGE_VERSION);
	asfd_mock_read(asfd, &r, 0, CMD_GEN, "whoareyou:" PACKAGE_VERSION);
	asfd_assert_write(asfd, &w, 0, CMD_GEN, "testclient");
	asfd_mock_read(asfd, &r, 0, CMD_GEN, "okpassword");
	asfd_assert_write(asfd, &w, 0, CMD_GEN, "password");
	asfd_mock_read(asfd, &r, 0, CMD_WARNING, "This is a version warning");
	asfd_mock_read(asfd, &r, 0, CMD_GEN, "ok");
}

static void setup_all_ok_version_warning_read_error(struct asfd *asfd)
{
	int r=0; int w=0;
	asfd_assert_write(asfd, &w,  0, CMD_GEN, "hello:" PACKAGE_VERSION);
	asfd_mock_read(asfd, &r,  0, CMD_GEN, "whoareyou:" PACKAGE_VERSION);
	asfd_assert_write(asfd, &w,  0, CMD_GEN, "testclient");
	asfd_mock_read(asfd, &r,  0, CMD_GEN, "okpassword");
	asfd_assert_write(asfd, &w,  0, CMD_GEN, "password");
	asfd_mock_read(asfd, &r,  0, CMD_WARNING, "This is a version warning");
	asfd_mock_read(asfd, &r, -1, CMD_GEN, "ok");
}

static void setup_not_ok(struct asfd *asfd)
{
	int r=0; int w=0;
	asfd_assert_write(asfd, &w, 0, CMD_GEN, "hello:" PACKAGE_VERSION);
	asfd_mock_read(asfd, &r, 0, CMD_GEN, "whoareyou");
	asfd_assert_write(asfd, &w, 0, CMD_GEN, "testclient");
	asfd_mock_read(asfd, &r, 0, CMD_GEN, "okpassword");
	asfd_assert_write(asfd, &w, 0, CMD_GEN, "password");
	asfd_mock_read(asfd, &r, 0, CMD_GEN, "notok");
}

static void setup_write_fail(struct asfd *asfd)
{
	int w=0;
	asfd_assert_write(asfd, &w, -1, CMD_GEN, "hello:" PACKAGE_VERSION);
}

static void setup_read_fail(struct asfd *asfd)
{
	int r=0; int w=0;
	asfd_assert_write(asfd, &w,  0, CMD_GEN, "hello:" PACKAGE_VERSION);
	asfd_mock_read(asfd, &r, -1, CMD_GEN, "whoareyou");
}

static void setup_read_fail_2(struct asfd *asfd)
{
	int r=0; int w=0;
	asfd_assert_write(asfd, &w,  0, CMD_GEN, "hello:" PACKAGE_VERSION);
	asfd_mock_read(asfd, &r,  0, CMD_GEN, "whoareyou");
	asfd_assert_write(asfd, &w,  0, CMD_GEN, "testclient");
	asfd_mock_read(asfd, &r, -1, CMD_GEN, "okpassword");
}

static void run_test(int expected_ret, const char *expected_server_version,
	void setup_callback(struct asfd *asfd))
{
	struct asfd *asfd;
	char *server_version=NULL;

	alloc_check_init();
	asfd=asfd_mock_setup(&reads, &writes);

	setup_callback(asfd);

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
	run_test( 0, PACKAGE_VERSION, setup_all_ok_server_version);
	run_test( 0, "",      setup_all_ok_server_version_empty);
	run_test( 0, PACKAGE_VERSION, setup_all_ok_version_warning);
	run_test(-1, PACKAGE_VERSION, setup_all_ok_version_warning_read_error);
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
