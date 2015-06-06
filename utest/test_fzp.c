#include <check.h>
#include <stdint.h>
#include <stdlib.h>
#include <stdio.h>
#include "test.h"
#include "../src/alloc.h"
#include "../src/fzp.h"

static const char *file="utest_fzp";
static const char *content="0123456789abcdefg";

static void tear_down(void)
{
	fail_unless(free_count==alloc_count);
	unlink(file);
}

static void setup_for_read(
	struct fzp *(*open_func)(const char *, const char *),
	const char *to_write)
{
	struct fzp *fzp;
	size_t len=strlen(to_write);
	unlink(file);
	fail_unless((fzp=open_func(file, "wb"))!=NULL);
	fail_unless(fzp_write(fzp, to_write, len)==len);
	fail_unless(!fzp_close(&fzp));
	fail_unless(fzp==NULL);
}

struct data
{
	size_t want;
	size_t got;
	const char *expected_str;
};

static struct data d[] = {
	{ 0,   0, "" },
	{ 3,   3, "012" },
	{ 16, 16, "0123456789abcdef" },
	{ 20, 17, "0123456789abcdefg" },
};

static void read_checks(
	struct fzp *(*open_func)(const char *, const char *),
	struct data *d)
{
	char buf[32]="";
	struct fzp *fzp;

	fail_unless((fzp=open_func(file, "rb"))!=NULL);
	fail_unless(fzp_read(fzp, buf, d->want)==d->got);
	fail_unless((d->want>d->got) == fzp_eof(fzp));
	fail_unless(!fzp_close(&fzp));
	fail_unless(fzp==NULL);

	ck_assert_str_eq(d->expected_str, buf);
}

static void do_read_tests(
	struct fzp *(*open_func)(const char *, const char *))
{
	setup_for_read(open_func, content);

	FOREACH(d) read_checks(open_func, &d[i]);

	tear_down();
}

START_TEST(test_fzp_read)
{
	do_read_tests(fzp_open);
}
END_TEST

START_TEST(test_fzp_gzread)
{
	do_read_tests(fzp_gzopen);
}
END_TEST

Suite *suite_fzp(void)
{
	Suite *s;
	TCase *tc_core;

	s=suite_create("fzp");

	tc_core=tcase_create("Core");

	tcase_add_test(tc_core, test_fzp_read);
	tcase_add_test(tc_core, test_fzp_gzread);
	suite_add_tcase(s, tc_core);

	return s;
}
