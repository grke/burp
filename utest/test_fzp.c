#include <check.h>
#include <stdint.h>
#include <stdlib.h>
#include <stdio.h>
#include "test.h"
#include "../src/alloc.h"
#include "../src/fzp.h"

static const char *file="utest_fzp";
static const char *content="0123456789abcdefg";

static void alloc_check(void)
{
	fail_unless(free_count==alloc_count);
}

static void tear_down(void)
{
	alloc_check();
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
	fail_unless(!fzp_flush(fzp));
	fail_unless(!fzp_close(&fzp));
	fail_unless(fzp==NULL);
}

struct rdata
{
	size_t want;
	size_t got;
	const char *expected_str;
};

static struct rdata rd[] = {
	{ 0,   0, "" },
	{ 3,   3, "012" },
	{ 16, 16, "0123456789abcdef" },
	{ 20, 17, "0123456789abcdefg" },
};

static void read_checks(
	struct fzp *(*open_func)(const char *, const char *),
	struct rdata *d)
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

struct sdata
{
	off_t pos;
};

static struct sdata sd[] = {
	{ 0 },
	{ 5 },
	{ 10 },
	{ 16 },
	{ 20 }
};

static void seek_checks(
	struct fzp *(*open_func)(const char *, const char *),
	struct sdata *d)
{
	struct fzp *fzp;

	fail_unless((fzp=open_func(file, "rb"))!=NULL);
	fail_unless(!fzp_seek(fzp, d->pos, SEEK_SET));
	fail_unless(fzp_tell(fzp)==d->pos);
	fail_unless(!fzp_close(&fzp));
	fail_unless(fzp==NULL);
}

static void do_read_tests(
	struct fzp *(*open_func)(const char *, const char *))
{
	setup_for_read(open_func, content);

	FOREACH(rd) read_checks(open_func, &rd[i]);

	tear_down();
}

static void do_seek_tests(
	struct fzp *(*open_func)(const char *, const char *))
{
	setup_for_read(open_func, content);

	FOREACH(sd) seek_checks(open_func, &sd[i]);

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

START_TEST(test_fzp_seek)
{
	do_seek_tests(fzp_open);
}
END_TEST

START_TEST(test_fzp_gzseek)
{
	do_seek_tests(fzp_gzopen);
}
END_TEST

START_TEST(test_fzp_null_pointer)
{
	struct fzp *fzp=NULL;
	fail_unless(!fzp_close(&fzp));
	fail_unless(!fzp_close(NULL));
	fail_unless(!fzp_read(NULL, NULL, 1));
	fail_unless(!fzp_write(NULL, NULL, 1));
	fail_unless(fzp_eof(NULL)==-1);
	fail_unless(fzp_flush(NULL)==EOF);
	fail_unless(fzp_seek(NULL, 1, SEEK_SET)==-1);
	fail_unless(fzp_tell(NULL)==-1);
	fail_unless(fzp_printf(NULL, "%s", "blah")==-1);
	alloc_check();
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
	tcase_add_test(tc_core, test_fzp_seek);
	tcase_add_test(tc_core, test_fzp_gzseek);
	tcase_add_test(tc_core, test_fzp_null_pointer);
	suite_add_tcase(s, tc_core);

	return s;
}
