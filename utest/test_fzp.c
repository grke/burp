#include "test.h"
#include "../src/alloc.h"
#include "../src/fzp.h"
#include "../src/handy.h"

static const char *file="utest_fzp";
static const char *content="0123456789abcdefg";

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
	fail_unless(fzp_read(fzp, buf, d->want)==(int)d->got);
	if(d->want > d->got)
		fail_unless(fzp_eof(fzp));
	else
		fail_unless(!fzp_eof(fzp));
	fail_unless(!fzp_close(&fzp));
	fail_unless(fzp==NULL);

	ck_assert_str_eq(d->expected_str, buf);
}

static void do_read_tests(
	struct fzp *(*open_func)(const char *, const char *))
{
	alloc_check_init();
	setup_for_read(open_func, content);
	FOREACH(rd) read_checks(open_func, &rd[i]);
	tear_down();
};

struct sdata
{
	off_t pos;
};

static struct sdata sd[] = {
	{ 0 },
	{ 5 },
	{ 10 },
	{ 16 },
	{ 20 } // It is OK to seek beyond the end of a file.
};

static void seek_checks(
	struct fzp *(*open_func)(const char *, const char *),
	struct sdata *d)
{
	struct fzp *fzp;

	fail_unless((fzp=open_func(file, "rb"))!=NULL);
	fail_unless(!fzp_seek(fzp, d->pos, SEEK_SET));
	fail_unless(fzp_tell(fzp)==d->pos);
	fail_unless(!fzp_eof(fzp));
	fail_unless(!fzp_close(&fzp));
	fail_unless(fzp==NULL);
}

static void do_seek_tests(
	struct fzp *(*open_func)(const char *, const char *))
{
	alloc_check_init();
	setup_for_read(open_func, content);
	FOREACH(sd) seek_checks(open_func, &sd[i]);
	tear_down();
};

#ifndef HAVE_WIN32
struct tdata
{
	off_t pos;
	const char *expected_str;
};

static struct tdata td[] = {
	{  0, "" },
	{  5, "01234" },
	{ 17, "0123456789abcdefg" },
	{ 20, "0123456789abcdefg" }
};

static void truncate_checks(
	struct fzp *(*open_func)(const char *, const char *),
	enum fzp_type type,
	struct tdata *d)
{
	char buf[32]="";
	struct fzp *fzp;

	fail_unless(!fzp_truncate(file, type, d->pos, 9 /* compression */));
	fail_unless((fzp=open_func(file, "rb"))!=NULL);
	fzp_read(fzp, buf, sizeof(buf));
	fail_unless(fzp_eof(fzp));
	fail_unless(!fzp_close(&fzp));
	fail_unless(fzp==NULL);

	ck_assert_str_eq(d->expected_str, buf);
}

static void do_truncate_tests(
	struct fzp *(*open_func)(const char *, const char *),
	enum fzp_type type)
{
	FOREACH(td)
	{
		alloc_check_init();
		setup_for_read(open_func, content);
		truncate_checks(open_func, type, &td[i]);
		tear_down();
	}
}
#endif

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

#ifndef HAVE_WIN32
START_TEST(test_fzp_truncate)
{
	do_truncate_tests(fzp_open, FZP_FILE);
}
END_TEST

START_TEST(test_fzp_gztruncate)
{
	do_truncate_tests(fzp_gzopen, FZP_COMPRESSED);
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
	fail_unless(fzp_truncate(NULL, FZP_FILE, 1, 9 /* compression */)==-1);
	fail_unless(fzp_printf(NULL, "%s", "blah")==-1);
	fzp_setlinebuf(NULL);
	fail_unless(fzp_gets(NULL, NULL, 0)==NULL);
	fail_unless(fzp_fileno(NULL)==-1);

	fzp_ERR_print_errors_fp(NULL);
	fail_unless(!fzp_PEM_read_X509(NULL));
	tear_down();
}
END_TEST
#endif

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
#ifndef HAVE_WIN32
	tcase_add_test(tc_core, test_fzp_truncate);
	tcase_add_test(tc_core, test_fzp_gztruncate);
	tcase_add_test(tc_core, test_fzp_null_pointer);
#endif
	suite_add_tcase(s, tc_core);

	return s;
}
