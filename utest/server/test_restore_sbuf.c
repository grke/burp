#include "../test.h"
#include "../../src/alloc.h"
#include "../../src/asfd.h"
#include "../../src/cmd.h"
#include "../../src/cntr.h"
#include "../../src/conf.h"
#include "../../src/fsops.h"
#include "../../src/iobuf.h"
#include "../../src/sbuf.h"
#include "../../src/server/restore_sbuf.h"
#include "../builders/build_asfd_mock.h"
#include "../builders/build_file.h"

#define BASE	"utest_server_restore_sbuf"

static struct ioevent_list areads;
static struct ioevent_list awrites;

static void setup_not_found_message(struct asfd *asfd, struct sbuf *sb)
{
	int w=0;
	char msg[256]="";
	snprintf(msg, sizeof(msg), "restore could not find %s (%s)\n",
		iobuf_to_printable(&sb->path),
		iobuf_to_printable(&sb->datapth));
	asfd_assert_write(asfd, &w, 0, CMD_WARNING, msg);
}

static void setup_could_not_open_message(struct asfd *asfd, const char *path)
{
	int w=0;
	char msg[256]="";
	snprintf(msg, sizeof(msg), "could not open %s\n", path);
	asfd_assert_write(asfd, &w, 0, CMD_WARNING, msg);
}

static void setup_no_md5sum(struct asfd *asfd, struct sbuf *sb)
{
	int w=0;
	char msg[256]="";
	snprintf(msg, sizeof(msg), "%s has no md5sum!\n",
		iobuf_to_printable(&sb->datapth));
	asfd_assert_write(asfd, &w, 0, CMD_WARNING, msg);
}

static void setup_md5sum_no_match(struct asfd *asfd, struct sbuf *sb)
{
	int w=0;
	char msg[256]="";
	snprintf(msg, sizeof(msg), "md5sum for '%s (%s)' did not match!\n",
		iobuf_to_printable(&sb->path),
		iobuf_to_printable(&sb->datapth));
	asfd_assert_write(asfd, &w, 0, CMD_WARNING, msg);
}

static void setup_md5sum_match(struct asfd *asfd, struct sbuf *sb)
{
	int w=0;
	asfd_assert_write(asfd, &w, 0, CMD_FILE, sb->path.buf);
}

static void setup_error_while_reading(struct asfd *asfd, const char *path)
{
	int w=0;
	char msg[256]="";
	snprintf(msg, sizeof(msg), "error while reading %s\n", path);
	asfd_assert_write(asfd, &w, 0, CMD_WARNING, msg);
}

static void clean(void)
{
	fail_unless(recursive_delete(BASE)==0);
}

static void tear_down(struct sbuf **sb, struct cntr **cntr,
	struct conf ***confs, struct asfd **asfd)
{
	clean();
	sbuf_free(sb);
	cntr_free(cntr);
	confs_free(confs);
	asfd_free(asfd);
	asfd_mock_teardown(&areads, &awrites);
	alloc_check();
}

static struct cntr *setup_cntr(void)
{
	struct cntr *cntr;
	fail_unless((cntr=cntr_alloc())!=NULL);
	fail_unless(!cntr_init(cntr, "testclient", getpid()));
	return cntr;
}

static struct conf **setup_confs(void)
{
	struct conf **confs;
	struct cntr *cntr;
	cntr=setup_cntr();
	fail_unless((confs=confs_alloc())!=NULL);
	fail_unless(!confs_init(confs));
	fail_unless(!set_cntr(confs[OPT_CNTR], cntr));
	return confs;
}

static struct sbuf *setup_sbuf(const char *path, const char *datapth,
	const char *endfile, int compression)
{
	struct sbuf *sb;
	fail_unless((sb=sbuf_alloc())!=NULL);
	if(path)
	{
		fail_unless((path=strdup_w(path, __func__))!=NULL);
		iobuf_from_str(&sb->path, CMD_FILE, (char *)path);
	}
	if(datapth)
	{
		fail_unless((datapth=strdup_w("/datapth", __func__))!=NULL);
		iobuf_from_str(&sb->datapth,
			CMD_FILE, (char *)datapth);
	}
	if(endfile)
	{
		fail_unless((endfile=strdup_w(endfile, __func__))!=NULL);
		iobuf_from_str(&sb->endfile, CMD_END_FILE, (char *)endfile);
	}

	sb->compression=compression;

	return sb;
}

START_TEST(test_verify_file_non_existent)
{
	struct asfd *asfd;
	struct cntr *cntr;
	struct sbuf *sb;
	const char *path="somepath";
	const char *best=BASE "/non_existent";

	clean();
	cntr=setup_cntr();
	sb=setup_sbuf(path, NULL, "0:0", 1/*compression*/);

	asfd=asfd_mock_setup(&areads, &awrites);
	setup_could_not_open_message(asfd, best);

	// Returns 0 so that the parent process continues.
	fail_unless(!verify_file(asfd, sb, 0 /*patches*/, best, cntr));
	fail_unless(cntr->ent[CMD_WARNING]->count==1);
	tear_down(&sb, &cntr, NULL, &asfd);
}
END_TEST

static void do_md5sum_test(const char *endfile, int warnings,
	void setup_callback(struct asfd *asfd, struct sbuf *sb))
{
	struct asfd *asfd;
	struct cntr *cntr;
	struct sbuf *sb;
	const char *path="somepath";
	const char *datapth="/datapth";
	const char *best=BASE "/existent";

	clean();
	cntr=setup_cntr();
	sb=setup_sbuf(path, datapth, endfile, 0/*compression*/);

	build_file(best, "blah");

	asfd=asfd_mock_setup(&areads, &awrites);
	setup_callback(asfd, sb);

	// Returns 0 so that the parent process continues.
	fail_unless(!verify_file(asfd, sb, 0 /*patches*/, best, cntr));
	fail_unless(cntr->ent[CMD_WARNING]->count==warnings);
	tear_down(&sb, &cntr, NULL, &asfd);
}

START_TEST(test_verify_file_no_md5sum)
{
	do_md5sum_test("0", 1/*warnings*/, setup_no_md5sum);
}
END_TEST

START_TEST(test_verify_file_md5sum_no_match)
{
	do_md5sum_test("0:0", 1 /*warnings*/, setup_md5sum_no_match);
}
END_TEST

START_TEST(test_verify_file_md5sum_match)
{
	do_md5sum_test("4:6f1ed002ab5595859014ebf0951522d9", 0/*warnings*/,
		setup_md5sum_match);
}
END_TEST

START_TEST(test_verify_file_gzip_read_failure)
{
	struct asfd *asfd;
	struct cntr *cntr;
	struct sbuf *sb;
	const char *path="somepath";
	const char *datapth="/datapth";
	const char *endfile="0:0";
	const char *best=BASE "/existent";
	const char *plain_text="some plain text";
	size_t s;
	struct fzp *fzp;
	s=strlen(plain_text);

	clean();
	cntr=setup_cntr();
	sb=setup_sbuf(path, datapth, endfile, 1/*compression*/);

	// Make a corrupt gzipped file.
	build_path_w(best);
	fail_unless((fzp=fzp_gzopen(best, "wb"))!=NULL);
	fail_unless(fzp_write(fzp, plain_text, s)==s);
	fail_unless(!fzp_close(&fzp));
	fail_unless((fzp=fzp_open(best, "r+b"))!=NULL);
	fail_unless(!fzp_seek(fzp, 10, SEEK_SET));
	fail_unless(fzp_write(fzp, "aa", 2)==2);
	fail_unless(!fzp_close(&fzp));

	asfd=asfd_mock_setup(&areads, &awrites);
	setup_error_while_reading(asfd, best);

	// Returns 0 so that the parent process continues.
	fail_unless(!verify_file(asfd, sb, 0 /*patches*/, best, cntr));
	fail_unless(cntr->ent[CMD_WARNING]->count==1);
	tear_down(&sb, &cntr, NULL, &asfd);
}
END_TEST

START_TEST(test_restore_file_not_found)
{
	struct asfd *asfd;
	struct sbuf *sb;
	struct conf **confs;
	struct cntr *cntr;

	clean();

	confs=setup_confs();
	sb=setup_sbuf("/path", "/datapth", NULL, 0);

	asfd=asfd_mock_setup(&areads, &awrites);
	setup_not_found_message(asfd, sb);

	// Passing in NULL bu means that the file will not be found, as there
	// are no backups to traverse.
	// The function should return 0, so that the calling function
	// can continue.
	fail_unless(!restore_file(
		asfd,
		NULL /*bu*/,
		sb,
		ACTION_RESTORE,
		NULL /*sdirs*/,
		confs
	));
	cntr=get_cntr(confs);
	fail_unless(cntr->ent[CMD_WARNING]->count==1);
	tear_down(&sb, NULL, &confs, &asfd);
}
END_TEST

Suite *suite_server_restore_sbuf(void)
{
	Suite *s;
	TCase *tc_core;

	s=suite_create("server_restore_sbuf");

	tc_core=tcase_create("Core");
	tcase_add_test(tc_core, test_verify_file_non_existent);
	tcase_add_test(tc_core, test_verify_file_no_md5sum);
	tcase_add_test(tc_core, test_verify_file_md5sum_no_match);
	tcase_add_test(tc_core, test_verify_file_md5sum_match);
	tcase_add_test(tc_core, test_verify_file_gzip_read_failure);
	tcase_add_test(tc_core, test_restore_file_not_found);
	suite_add_tcase(s, tc_core);

	return s;
}
