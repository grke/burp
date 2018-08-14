#include "test.h"
#include "../src/alloc.h"
#include "../src/asfd.h"
#include "../src/async.h"
#include "../src/ssl.h"

static struct async *setup(void)
{
	struct async *as;
	fail_unless((as=async_alloc())!=NULL);
	as->init(as, 0);
	return as;
}

static void tear_down(struct async **as)
{
	async_asfd_free_all(as);
	alloc_check();
}

static void checks(struct asfd *asfd,
	enum asfd_streamtype streamtype,
	int fd,
	const char *listen,
	SSL *ssl,
	const char *desc,
	enum asfd_fdtype fdtype,
	int attempt_reads)
{
	char fulldesc[256];
	snprintf(fulldesc, sizeof(fulldesc), "%s %d", desc, fd);
	fail_unless(asfd->streamtype==streamtype);
	fail_unless(asfd->fd==fd);
	fail_unless(!strcmp(asfd->listen, listen));
	fail_unless(asfd->ssl==ssl);
	fail_unless(!strcmp(asfd->desc, fulldesc));
	fail_unless(asfd->fdtype==fdtype);
	fail_unless(asfd->attempt_reads==attempt_reads);
}

START_TEST(test_asfd_alloc)
{
	struct asfd *asfd;
	fail_unless((asfd=asfd_alloc())!=NULL);
	asfd_free(&asfd);
	alloc_check();
}
END_TEST

START_TEST(test_setup_asfd_error)
{
	struct async *as;
	struct asfd *asfd;
	int fd=-1;
	as=setup();
	fail_unless((asfd=setup_asfd(as, "desc", &fd, /*listen*/""))==NULL);
	fail_unless(fd==-1);
	tear_down(&as);
}
END_TEST

START_TEST(test_setup_asfd_ssl)
{
	SSL *ssl;
	SSL_CTX *ctx;
	SSL_METHOD *meth;
	struct async *as;
	struct asfd *asfd;
	int fd=100;
	const char *desc="desc";
	as=setup();
	ssl_load_globals();
	fail_unless((meth=(SSL_METHOD *)SSLv23_method())!=NULL);
	ctx=(SSL_CTX *)SSL_CTX_new(meth);
	ssl=SSL_new(ctx);
	fail_unless((asfd=setup_asfd_ssl(as, desc, &fd, ssl))!=NULL);
	checks(asfd, ASFD_STREAM_STANDARD, 100, /*listen*/"",
		ssl, "desc", ASFD_FD_UNSET, /*attempt_read*/1);
	fail_unless(fd==-1);
	tear_down(&as);
	ssl_destroy_ctx(ctx);
}
END_TEST

START_TEST(test_setup_asfd)
{
	struct async *as;
	struct asfd *asfd;
	int fd=100;
	const char *listen="0.0.0.0:500";
	const char *desc="desc";
	as=setup();
	fail_unless((asfd=setup_asfd(as, desc, &fd, listen))!=NULL);
	checks(asfd, ASFD_STREAM_STANDARD, 100, listen,
		/*ssl*/NULL, "desc", ASFD_FD_UNSET, /*attempt_read*/1);
	fail_unless(fd==-1);
	tear_down(&as);
}
END_TEST

START_TEST(test_setup_asfd_linebuf_read)
{
	struct async *as;
	struct asfd *asfd;
	int fd=100;
	const char *desc="desc";
	as=setup();
	fail_unless((asfd=setup_asfd_linebuf_read(as, desc, &fd))!=NULL);
	checks(asfd, ASFD_STREAM_LINEBUF, 100, /*listen*/"",
		/*ssl*/NULL, "desc", ASFD_FD_UNSET, /*attempt_read*/1);
	fail_unless(fd==-1);
	tear_down(&as);
}
END_TEST

START_TEST(test_setup_asfd_linebuf_write)
{
	struct async *as;
	struct asfd *asfd;
	int fd=100;
	const char *desc="desc";
	as=setup();
	fail_unless((asfd=setup_asfd_linebuf_write(as, desc, &fd))!=NULL);
	checks(asfd, ASFD_STREAM_LINEBUF, 100, /*listen*/"",
		/*ssl*/NULL, "desc", ASFD_FD_UNSET, /*attempt_read*/0);
	fail_unless(fd==-1);
	tear_down(&as);
}
END_TEST

START_TEST(test_setup_asfd_stdin)
{
	struct async *as;
	struct asfd *asfd;
	as=setup();
	fail_unless((asfd=setup_asfd_stdin(as))!=NULL);
	checks(asfd, ASFD_STREAM_LINEBUF, fileno(stdin), /*listen*/"",
		/*ssl*/NULL, "stdin", ASFD_FD_UNSET, /*attempt_read*/1);
	tear_down(&as);
}
END_TEST

START_TEST(test_setup_asfd_stdout)
{
	struct async *as;
	struct asfd *asfd;
	as=setup();
	fail_unless((asfd=setup_asfd_stdout(as))!=NULL);
	checks(asfd, ASFD_STREAM_LINEBUF, fileno(stdout), /*listen*/"",
		/*ssl*/NULL, "stdout", ASFD_FD_UNSET, /*attempt_read*/0);
	tear_down(&as);
}
END_TEST

START_TEST(test_setup_asfd_ncurses_stdin)
{
#ifdef HAVE_NCURSES
	struct async *as;
	struct asfd *asfd;
	as=setup();
	fail_unless((asfd=setup_asfd_ncurses_stdin(as))!=NULL);
	checks(asfd, ASFD_STREAM_NCURSES_STDIN, fileno(stdin), /*listen*/"",
		/*ssl*/NULL, "stdin", ASFD_FD_UNSET, /*attempt_read*/1);
	tear_down(&as);
#endif
}
END_TEST

START_TEST(test_setup_asfd_twice)
{
	struct async *as;
	struct asfd *in;
	struct asfd *out;
	as=setup();
	fail_unless((in=setup_asfd_stdin(as))!=NULL);
	fail_unless((out=setup_asfd_stdout(as))!=NULL);
	fail_unless(as->asfd==in);
	fail_unless(in->next==out);
	fail_unless(out->next==NULL);
	tear_down(&as);
}
END_TEST

Suite *suite_asfd(void)
{
	Suite *s;
	TCase *tc_core;

	s=suite_create("asfd");

	tc_core=tcase_create("Core");

	tcase_add_test(tc_core, test_asfd_alloc);
	tcase_add_test(tc_core, test_setup_asfd_error);
	tcase_add_test(tc_core, test_setup_asfd_ssl);
	tcase_add_test(tc_core, test_setup_asfd);
	tcase_add_test(tc_core, test_setup_asfd_linebuf_read);
	tcase_add_test(tc_core, test_setup_asfd_linebuf_write);
	tcase_add_test(tc_core, test_setup_asfd_stdin);
	tcase_add_test(tc_core, test_setup_asfd_stdout);
	tcase_add_test(tc_core, test_setup_asfd_twice);
	tcase_add_test(tc_core, test_setup_asfd_ncurses_stdin);
	suite_add_tcase(s, tc_core);

	return s;
}

