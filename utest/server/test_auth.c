#include "../test.h"
#include "../../src/asfd.h"
#include "../../src/conffile.h"
#include "../../src/fsops.h"
#include "../../src/iobuf.h"
#include "../../src/server/auth.h"
#include "../builders/build.h"
#include "../builders/build_asfd_mock.h"
#include "../builders/build_file.h"

#define BASE		"utest_server_auth"
#define CONFFILE	BASE "/burp.conf"

int CNAME_LOWERCASE=0;

static void clean(void)
{
	fail_unless(!recursive_delete(BASE));
	fail_unless(!recursive_delete(CLIENTCONFDIR));
}

struct pdata
{
	int expected;
	const char *passwd;
	const char *plain_text;
};

static struct pdata p[] = {
	// 1 is success, 0 is failure.
	{ 1, "hiH9IOyyrrl4k", "ifpqgio" },
	{ 0, "hiH9IOyyrrl4k", "ifpqgia" },
#ifndef HAVE_NETBSD_OS
#ifndef HAVE_DARWIN_OS
	{ 1, "$6$dYCzeXf3$Vue9VQ49lBLtK7d273FxKYsWrF1WGwr3Th2GBCghj0WG61o/bXxEal/11pCdvWqN/Y1iSiOblqZhitBsqAOVe1", "testuser" },
	{ 0, "x6$dYCzeXf3$Vue9VQ49lBLtK7d273FxKYsWrF1WGwr3Th2GBCghj0WG61o/bXxEal/11pCdvWqN/Y1iSiOblqZhitBsqAOVe1", "testuser" },
	{ 0, "x6$dYCzeXf3$Vue9VQ49lBLtK7d273FxKYsWrF1WGwr3Th2GBCghj0WG61o/bXxEal/11pCdvWqN/Y1iSiOblqZhitBsqAOVe1", NULL },
#endif
#endif
	{ 0, NULL, "testuser" },
	{ 0, "123", "testuser" }
};

START_TEST(test_check_passwd)
{
        FOREACH(p)
	{
		int result=check_passwd(p[i].passwd, p[i].plain_text);
		fail_unless(result==p[i].expected);
	}

}
END_TEST

static struct ioevent_list reads;
static struct ioevent_list writes;

static void do_test(
	int expected_ret,
	void setup_callback(struct asfd *asfd)
	)
{
	struct asfd *asfd;
	struct conf **globalcs=NULL;
	struct conf **cconfs=NULL;

	clean();

        fail_unless((globalcs=confs_alloc())!=NULL);
        fail_unless((cconfs=confs_alloc())!=NULL);
	confs_init(globalcs);
	confs_init(cconfs);

	build_file(CONFFILE, MIN_CLIENT_CONF);
	fail_unless(!conf_load_global_only(CONFFILE, globalcs));

	fail_unless(!set_string(globalcs[OPT_CLIENTCONFDIR], CLIENTCONFDIR));

	fail_unless(!set_int(cconfs[OPT_CNAME_LOWERCASE], CNAME_LOWERCASE));

	asfd=asfd_mock_setup(&reads, &writes);

	setup_callback(asfd);

	fail_unless(authorise_server(
		asfd,
		globalcs,
		cconfs
	)==expected_ret);

	asfd_free(&asfd);
	asfd_mock_teardown(&reads, &writes);
	confs_free(&globalcs);
	confs_free(&cconfs);
	alloc_check();

	clean();
}

static void setup_initial_error(struct asfd *asfd)
{
	int r=0;
	asfd_mock_read(asfd, &r, -1, CMD_GEN, "adfdff");
}

static void setup_no_hello(struct asfd *asfd)
{
	int r=0;
	asfd_mock_read(asfd, &r, 0, CMD_GEN, "blarg");
}

static void setup_happy_path(struct asfd *asfd)
{
	int r=0;
	int w=0;
	const char *cnames[] = {"testclient", NULL};
	build_clientconfdir_files(cnames, "password=mypass\nkeep=4\n");
	asfd_mock_read(asfd, &r, 0, CMD_GEN, "hello:" VERSION);
	asfd_assert_write(asfd, &w, 0, CMD_GEN, "whoareyou:" VERSION);
	asfd_mock_read(asfd, &r, 0, CMD_GEN, "testclient");
	asfd_assert_write(asfd, &w, 0, CMD_GEN, "okpassword");
	asfd_mock_read(asfd, &r, 0, CMD_GEN, "mypass");
	asfd_assert_write(asfd, &w, 0, CMD_GEN, "ok");
}

static void setup_okpassword_error(struct asfd *asfd)
{
	int r=0;
	int w=0;
	asfd_mock_read(asfd, &r, 0, CMD_GEN, "hello:" VERSION);
	asfd_assert_write(asfd, &w, 0, CMD_GEN, "whoareyou:" VERSION);
	asfd_mock_read(asfd, &r, 0, CMD_GEN, "testclient");
	asfd_assert_write(asfd, &w, -1, CMD_GEN, "okpassword");
}

static void setup_whoareyou_error(struct asfd *asfd)
{
	int r=0;
	int w=0;
	asfd_mock_read(asfd, &r, 0, CMD_GEN, "hello:" VERSION);
	asfd_assert_write(asfd, &w, -1, CMD_GEN, "whoareyou:" VERSION);
}

static void setup_happy_path_version_unknown(struct asfd *asfd)
{
	int r=0;
	int w=0;
	const char *cnames[] = {"testclient", NULL};
	build_clientconfdir_files(cnames, "password=mypass\nkeep=4\n");
	asfd_mock_read(asfd, &r, 0, CMD_GEN, "hello");
	asfd_assert_write(asfd, &w, 0, CMD_GEN, "whoareyou");
	asfd_mock_read(asfd, &r, 0, CMD_GEN, "testclient");
	asfd_assert_write(asfd, &w, 0, CMD_GEN, "okpassword");
	asfd_mock_read(asfd, &r, 0, CMD_GEN, "mypass");
	asfd_assert_write(asfd, &w, 0, CMD_WARNING, "Client 'testclient' has an unknown version. Please upgrade.\n");
	asfd_assert_write(asfd, &w, 0, CMD_GEN, "ok");
}

static void setup_happy_path_version_mismatch(struct asfd *asfd)
{
	int r=0;
	int w=0;
	const char *cnames[] = {"testclient", NULL};
	build_clientconfdir_files(cnames, "password=mypass\nkeep=4\n");
	asfd_mock_read(asfd, &r, 0, CMD_GEN, "hello:2.0.0");
	asfd_assert_write(asfd, &w, 0, CMD_GEN, "whoareyou:" VERSION);
	asfd_mock_read(asfd, &r, 0, CMD_GEN, "testclient");
	asfd_assert_write(asfd, &w, 0, CMD_GEN, "okpassword");
	asfd_mock_read(asfd, &r, 0, CMD_GEN, "mypass");
	asfd_assert_write(asfd, &w, 0, CMD_WARNING, "Client 'testclient' version '2.0.0' does not match server version '" VERSION "'. An upgrade is recommended.\n");
	asfd_assert_write(asfd, &w, 0, CMD_GEN, "ok");
}

static void setup_wrong_password(struct asfd *asfd)
{
	int r=0;
	int w=0;
	const char *cnames[] = {"testclient", NULL};
	build_clientconfdir_files(cnames, "password=mypass\nkeep=4\n");
	asfd_mock_read(asfd, &r, 0, CMD_GEN, "hello:" VERSION);
	asfd_assert_write(asfd, &w, 0, CMD_GEN, "whoareyou:" VERSION);
	asfd_mock_read(asfd, &r, 0, CMD_GEN, "testclient");
	asfd_assert_write(asfd, &w, 0, CMD_GEN, "okpassword");
	asfd_mock_read(asfd, &r, 0, CMD_GEN, "wrongpass");
}

static void setup_no_password_configured(struct asfd *asfd)
{
	int r=0;
	int w=0;
	const char *cnames[] = {"testclient", NULL};
	build_clientconfdir_files(cnames, NULL);
	asfd_mock_read(asfd, &r, 0, CMD_GEN, "hello:" VERSION);
	asfd_assert_write(asfd, &w, 0, CMD_GEN, "whoareyou:" VERSION);
	asfd_mock_read(asfd, &r, 0, CMD_GEN, "testclient");
	asfd_assert_write(asfd, &w, 0, CMD_GEN, "okpassword");
	asfd_mock_read(asfd, &r, 0, CMD_GEN, "mypass");
}

static void setup_passwd_failed(struct asfd *asfd)
{
	int r=0;
	int w=0;
	const char *cnames[] = {"testclient", NULL};
	build_clientconfdir_files(cnames, "passwd=hiH9IOyyrrl4k\nkeep=4\n");
	asfd_mock_read(asfd, &r, 0, CMD_GEN, "hello:" VERSION);
	asfd_assert_write(asfd, &w, 0, CMD_GEN, "whoareyou:" VERSION);
	asfd_mock_read(asfd, &r, 0, CMD_GEN, "testclient");
	asfd_assert_write(asfd, &w, 0, CMD_GEN, "okpassword");
	asfd_mock_read(asfd, &r, 0, CMD_GEN, "dafklfd");
}

static void setup_no_keep_configured(struct asfd *asfd)
{
	int r=0;
	int w=0;
	const char *cnames[] = {"testclient", NULL};
	build_clientconfdir_files(cnames, "password=mypass");
	asfd_mock_read(asfd, &r, 0, CMD_GEN, "hello:" VERSION);
	asfd_assert_write(asfd, &w, 0, CMD_GEN, "whoareyou:" VERSION);
	asfd_mock_read(asfd, &r, 0, CMD_GEN, "testclient");
	asfd_assert_write(asfd, &w, 0, CMD_GEN, "okpassword");
	asfd_mock_read(asfd, &r, 0, CMD_GEN, "mypass");
}

static void setup_lower_failed(struct asfd *asfd)
{
	int r=0;
	int w=0;
	const char *cnames[] = {"testclient", NULL};
	build_clientconfdir_files(cnames, "password=mypass\nkeep=4\n");
	asfd_mock_read(asfd, &r, 0, CMD_GEN, "hello:" VERSION);
	asfd_assert_write(asfd, &w, 0, CMD_GEN, "whoareyou:" VERSION);
	asfd_mock_read(asfd, &r, 0, CMD_GEN, "TESTCLIENT");
	asfd_assert_write(asfd, &w, 0, CMD_GEN, "okpassword");
	asfd_mock_read(asfd, &r, 0, CMD_GEN, "mypass");
}

static void setup_lower_ok(struct asfd *asfd)
{
	int r=0;
	int w=0;
	const char *cnames[] = {"testclient", NULL};
	build_clientconfdir_files(cnames, "password=mypass\nkeep=4\n");
	asfd_mock_read(asfd, &r, 0, CMD_GEN, "hello:" VERSION);
	asfd_assert_write(asfd, &w, 0, CMD_GEN, "whoareyou:" VERSION);
	asfd_mock_read(asfd, &r, 0, CMD_GEN, "TESTCLIENT");
	asfd_assert_write(asfd, &w, 0, CMD_GEN, "okpassword");
	asfd_mock_read(asfd, &r, 0, CMD_GEN, "mypass");
	asfd_assert_write(asfd, &w, 0, CMD_GEN, "ok");
}

START_TEST(test_authorise_server)
{
	do_test(-1, setup_initial_error);
	do_test(-1, setup_no_hello);
	do_test(0,  setup_happy_path);
	do_test(0,  setup_happy_path_version_unknown);
	do_test(0,  setup_happy_path_version_mismatch);
	do_test(-1, setup_whoareyou_error);
	do_test(-1, setup_okpassword_error);
	do_test(-1, setup_wrong_password);
	do_test(-1, setup_no_password_configured);
	do_test(-1, setup_passwd_failed);
	do_test(-1, setup_no_keep_configured);
	//do_test(-1, setup_lower_failed);
	CNAME_LOWERCASE=1;
	do_test(0, setup_lower_ok);
}
END_TEST

Suite *suite_server_auth(void)
{
	Suite *s;
	TCase *tc_core;

	s=suite_create("server_auth");

	tc_core=tcase_create("Core");

	tcase_add_test(tc_core, test_check_passwd);
	tcase_add_test(tc_core, test_authorise_server);
	suite_add_tcase(s, tc_core);

	return s;
}
