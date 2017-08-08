#include "../test.h"
#include "../../src/asfd.h"
#include "../../src/cntr.h"
#include "../../src/fsops.h"
#include "../../src/iobuf.h"
#include "../../src/server/autoupgrade.h"
#include "../builders/build.h"
#include "../builders/build_asfd_mock.h"
#include "../builders/build_file.h"

#define BASE		"utest_server_autoupgrade"
#define OS		"my_os"

static void clean(void)
{
	fail_unless(!recursive_delete(BASE));
}

static struct ioevent_list reads;
static struct ioevent_list writes;

static void do_test(
	int expected_ret,
	long ser_ver,
	long cli_ver,
	const char *autoupgrade_dir,
	void setup_callback(struct asfd *asfd)
	)
{
	struct asfd *asfd;
	struct cntr *cntr;

	clean();

	fail_unless((cntr=cntr_alloc())!=NULL);
	cntr_init(cntr, "my_cntr", getpid());

	asfd=asfd_mock_setup(&reads, &writes);

	setup_callback(asfd);

	fail_unless(autoupgrade_server(
		asfd,
		ser_ver,
		cli_ver,
		OS,
		cntr,
		autoupgrade_dir
	)==expected_ret);

	asfd_free(&asfd);
	asfd_mock_teardown(&reads, &writes);
	cntr_free(&cntr);
	alloc_check();

	clean();
}

static void setup_do_not_autoupgrade(struct asfd *asfd)
{
	int w=0;
	asfd_assert_write(asfd, &w, 0, CMD_GEN, "do not autoupgrade");
}

static void setup_no_autoupgrade_dir(struct asfd *asfd)
{
	setup_do_not_autoupgrade(asfd);
}

static void setup_files(int script_top, int script_specific, int package)
{
	char path[256];
	if(script_top)
	{
		snprintf(path, sizeof(path), "%s/%s/script",
			BASE, OS);
		build_file(path, "");
	}
	if(script_specific)
	{
		snprintf(path, sizeof(path), "%s/%s/%s/script",
			BASE, OS, PACKAGE_VERSION);
		build_file(path, "");
	}
	if(package)
	{
		snprintf(path, sizeof(path), "%s/%s/%s/package",
			BASE, OS, PACKAGE_VERSION);
		build_file(path, "");
	}
}

static void setup_newer_version_client(struct asfd *asfd)
{
	setup_files(1, 1, 1);
	setup_do_not_autoupgrade(asfd);
}

static void setup_same_version_client(struct asfd *asfd)
{
	setup_files(1, 1, 1);
	setup_do_not_autoupgrade(asfd);
}

static void setup_autoupgrade_ok_but_error(struct asfd *asfd)
{
	int w=0;
	asfd_assert_write(asfd, &w, -1, CMD_GEN, "autoupgrade ok");
}

static void setup_older_version_client(struct asfd *asfd)
{
	setup_files(1, 1, 1);
	setup_autoupgrade_ok_but_error(asfd);
}

static void setup_script_specific_only(struct asfd *asfd)
{
	setup_files(1, 0, 0);
	setup_do_not_autoupgrade(asfd);
}

static void setup_script_top_only(struct asfd *asfd)
{
	setup_files(0, 1, 0);
	setup_do_not_autoupgrade(asfd);
}

static void setup_package_only(struct asfd *asfd)
{
	setup_files(0, 0, 1);
	setup_do_not_autoupgrade(asfd);
}

static void setup_broken_script_path(struct asfd *asfd)
{
	// This will create a directory where a file should be.
	char path[256];
	snprintf(path, sizeof(path), "%s/%s/script/blah",
		BASE, OS);
	build_file(path, "");
	setup_files(0, 0, 1);
	setup_do_not_autoupgrade(asfd);
}

static void setup_broken_package_path(struct asfd *asfd)
{
	// This will create a directory where a file should be.
	char path[256];
	snprintf(path, sizeof(path), "%s/%s/%s/package/blah",
		BASE, OS, PACKAGE_VERSION);
	build_file(path, "");
	setup_files(1, 0, 0);
	setup_do_not_autoupgrade(asfd);
}

START_TEST(test_autoupgrade_server)
{
	do_test(0, 0, 0, NULL, setup_no_autoupgrade_dir);
	do_test(0, 100, 200, BASE, setup_newer_version_client);
	do_test(0, 100, 100, BASE, setup_same_version_client);
	do_test(-1, 200, 100, BASE, setup_older_version_client);

	do_test(0, 200, 100, BASE, setup_script_specific_only);
	do_test(0, 200, 100, BASE, setup_script_top_only);
	do_test(0, 200, 100, BASE, setup_package_only);

	do_test(-1, 200, 100, BASE, setup_broken_script_path);
	do_test(-1, 200, 100, BASE, setup_broken_package_path);
}
END_TEST

Suite *suite_server_autoupgrade(void)
{
	Suite *s;
	TCase *tc_core;

	s=suite_create("server_autoupgrade");

	tc_core=tcase_create("Core");

	tcase_add_test(tc_core, test_autoupgrade_server);

	suite_add_tcase(s, tc_core);

	return s;
}
