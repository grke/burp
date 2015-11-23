#include "../../test.h"
#include "../../../src/alloc.h"
#include "../../../src/fsops.h"
#include "../../../src/server/protocol1/bedup.h"
#include "../../builders/build_file.h"

#define BASE	"utest_bedup"

static void setup(void)
{
	fail_unless(!recursive_delete(BASE));
}

static void tear_down(void)
{
	fail_unless(!recursive_delete(BASE));
	alloc_check();
}

static void bad_options(int argc, const char *argv[])
{
	fail_unless(run_bedup(argc, (char **)argv)==1);
	tear_down();
}

START_TEST(test_bedup_non_burp_no_dirs)
{
	const char *argv[]={"utest", "-n"};
	bad_options(ARR_LEN(argv), argv);
}
END_TEST

START_TEST(test_bedup_non_burp_config_file)
{
	const char *argv[]={"utest", "-n", "-c", "burp.conf"};
	bad_options(ARR_LEN(argv), argv);
}
END_TEST

START_TEST(test_bedup_non_burp_groups)
{
	const char *argv[]={"utest", "-n", "-g", "group"};
	bad_options(ARR_LEN(argv), argv);
}
END_TEST

START_TEST(test_bedup_burp_max_links)
{
	const char *argv[]={"utest", "-m", "32"};
	bad_options(ARR_LEN(argv), argv);
}
END_TEST

START_TEST(test_bedup_delete_and_link)
{
	const char *argv[]={"utest", "-d", "-l"};
	bad_options(ARR_LEN(argv), argv);
}
END_TEST

START_TEST(test_bedup_burp_delete)
{
	const char *argv[]={"utest", "-d"};
	bad_options(ARR_LEN(argv), argv);
}
END_TEST

START_TEST(test_bedup_burp_extra_args)
{
	const char *argv[]={"utest", "-v", "blah"};
	bad_options(ARR_LEN(argv), argv);
}
END_TEST

START_TEST(test_bedup_non_burp_max_links_low)
{
	const char *argv[]={"utest", "-n", "-m", "1", "dir"};
	bad_options(ARR_LEN(argv), argv);
}
END_TEST

START_TEST(test_bedup_usage1)
{
	const char *argv[]={"utest", "-h"};
	bad_options(ARR_LEN(argv), argv);
}
END_TEST

START_TEST(test_bedup_usage2)
{
	const char *argv[]={"utest", "-?"};
	bad_options(ARR_LEN(argv), argv);
}
END_TEST

START_TEST(test_bedup_version)
{
	const char *argv[]={"utest", "-V"};
	fail_unless(run_bedup(ARR_LEN(argv), (char **)argv)==0);
	tear_down();
}
END_TEST

static void do_non_burp_simple(int argc, const char *argv[],
	struct stat *stat1, struct stat *stat2)
{
	const char *file1=BASE "/file1";
	const char *file2=BASE "/file2";
	const char *content="my content";
	setup();
	build_file(file1, content);
	build_file(file2, content);
	fail_unless(!run_bedup(argc, (char **)argv));
	fail_unless(!lstat(file1, stat1));
	fail_unless(!lstat(file2, stat2));
}

START_TEST(test_bedup_non_burp_simple)
{
	struct stat stat1;
	struct stat stat2;
	const char *argv[]={"utest", "-n", BASE};
	do_non_burp_simple(ARR_LEN(argv), argv, &stat1, &stat2);
	fail_unless(stat1.st_ino!=stat2.st_ino);
	tear_down();
}
END_TEST

START_TEST(test_bedup_non_burp_simple_link)
{
	struct stat stat1;
	struct stat stat2;
	const char *argv[]={"utest", "-n", "-l", BASE};
	do_non_burp_simple(ARR_LEN(argv), argv, &stat1, &stat2);
	fail_unless(stat1.st_ino==stat2.st_ino);
	tear_down();
}
END_TEST

Suite *suite_server_protocol1_bedup(void)
{
	Suite *s;
	TCase *tc_core;

	s=suite_create("server_protocol1_bedup");

	tc_core=tcase_create("Core");
	tcase_add_test(tc_core, test_bedup_non_burp_no_dirs);
	tcase_add_test(tc_core, test_bedup_non_burp_config_file);
	tcase_add_test(tc_core, test_bedup_non_burp_groups);
	tcase_add_test(tc_core, test_bedup_burp_max_links);
	tcase_add_test(tc_core, test_bedup_delete_and_link);
	tcase_add_test(tc_core, test_bedup_burp_delete);
	tcase_add_test(tc_core, test_bedup_burp_extra_args);
	tcase_add_test(tc_core, test_bedup_non_burp_max_links_low);
	tcase_add_test(tc_core, test_bedup_usage1);
	tcase_add_test(tc_core, test_bedup_usage2);
	tcase_add_test(tc_core, test_bedup_version);
	tcase_add_test(tc_core, test_bedup_non_burp_simple);
	tcase_add_test(tc_core, test_bedup_non_burp_simple_link);
	suite_add_tcase(s, tc_core);

	return s;
}
