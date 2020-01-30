#include "../test.h"
#include "../../src/alloc.h"
#include "../../src/asfd.h"
#include "../../src/bu.h"
#include "../../src/fsops.h"
#include "../../src/iobuf.h"
#include "../../src/sbuf.h"
#include "../../src/server/bu_get.h"
#include "../../src/server/list.h"
#include "../../src/server/sdirs.h"
#include "../builders/build.h"
#include "../builders/build_asfd_mock.h"

#define BASE	"utest_server_list"

static struct ioevent_list reads;
static struct ioevent_list writes;

static void tear_down(struct asfd **asfd, struct sdirs **sdirs)
{
	asfd_free(asfd);
	asfd_mock_teardown(&reads, &writes);
	sdirs_free(sdirs);
	fail_unless(recursive_delete(BASE)==0);
	alloc_check();
}

static struct sdirs *setup_sdirs(struct sd *s, int slen, enum protocol protocol)
{
	struct sdirs *sdirs;
	fail_unless(recursive_delete(BASE)==0);
	fail_unless((sdirs=sdirs_alloc())!=NULL);
	fail_unless(!sdirs_init(sdirs, protocol,
		BASE, // directory
		"utestclient", // cname
		NULL, // client_lockdir
		"a_group", // dedup_group
		NULL // manual_delete
		));
	build_storage_dirs(sdirs, s, slen);
	return sdirs;
}

static struct sd sd1[] = {
	{ "0000001 1970-01-01 00:00:00", 1, 1, BU_CURRENT|BU_DELETABLE }
};

static struct sd sd123[] = {
	{ "0000001 1970-01-01 00:00:00", 1, 1, BU_DELETABLE },
	{ "0000002 1970-01-02 00:00:00", 2, 2, 0 },
	{ "0000003 1970-01-03 00:00:00", 3, 3, BU_CURRENT }
};

static struct sd fp1[] = {
	{ "0000001 1970-01-01 00:00:00", 0, 0, 0 }
};

static struct sd fp2[] = {
	{ "0000002 1970-01-02 00:00:00", 0, 0, 0 }
};

static struct sd fp3[] = {
	{ "0000003 1970-01-03 00:00:00", 0, 0, 0 }
};

static struct sd fp123[] = {
	{ "0000001 1970-01-01 00:00:00", 0, 0, 0 },
	{ "0000002 1970-01-02 00:00:00", 0, 0, 0 },
	{ "0000003 1970-01-03 00:00:00", 0, 0, 0 }
};

static void setup_asfd_no_backups(struct asfd *asfd)
{
	int w=0;
	asfd_assert_write(asfd, &w, 0, CMD_MESSAGE, "no backups");
}

static void setup_asfd_bad_regex(struct asfd *asfd)
{
	int w=0;
	asfd_assert_write(asfd, &w, 0,
		CMD_ERROR, "unable to compile regex: *\n");
}

static void setup_asfd_1del(struct asfd *asfd)
{
	int w=0;
	asfd_assert_write(asfd, &w, 0,
		CMD_TIMESTAMP, "0000001 1970-01-01 00:00:00 (deletable)");
}

static void setup_asfd_1(struct asfd *asfd)
{
	int w=0;
	asfd_assert_write(asfd, &w, 0,
		CMD_TIMESTAMP, "0000001 1970-01-01 00:00:00");
}

static void setup_asfd_2(struct asfd *asfd)
{
	int w=0;
	asfd_assert_write(asfd, &w, 0,
		CMD_TIMESTAMP, "0000002 1970-01-02 00:00:00");
}

static void setup_asfd_3(struct asfd *asfd)
{
	int w=0;
	asfd_assert_write(asfd, &w, 0,
		CMD_TIMESTAMP, "0000003 1970-01-03 00:00:00");
}

static void setup_asfd_1del_2_3(struct asfd *asfd)
{
	int w=0;
	asfd_assert_write(asfd, &w, 0,
		CMD_TIMESTAMP, "0000001 1970-01-01 00:00:00 (deletable)");
	asfd_assert_write(asfd, &w, 0,
		CMD_TIMESTAMP, "0000002 1970-01-02 00:00:00");
	asfd_assert_write(asfd, &w, 0,
		CMD_TIMESTAMP, "0000003 1970-01-03 00:00:00");
}

static void setup_asfd_1_2_3(struct asfd *asfd)
{
	int w=0;
	asfd_assert_write(asfd, &w, 0,
		CMD_TIMESTAMP, "0000001 1970-01-01 00:00:00");
	asfd_assert_write(asfd, &w, 0,
		CMD_TIMESTAMP, "0000002 1970-01-02 00:00:00");
	asfd_assert_write(asfd, &w, 0,
		CMD_TIMESTAMP, "0000003 1970-01-03 00:00:00");
}

static void setup_asfd_not_found(struct asfd *asfd)
{
	int w=0;
	asfd_assert_write(asfd, &w, 0, CMD_MESSAGE, "backup not found");
}

static void setup_asfd_1del_write_failure(struct asfd *asfd)
{
	int w=0;
	asfd_assert_write(asfd, &w, -1,
		CMD_TIMESTAMP, "0000001 1970-01-01 00:00:00 (deletable)");
}

static int list_server_callback_count=0;
static int list_server_callback_ret=0;
static struct sd *list_server_callback_sd=NULL;
static char *list_server_callback_fp_prefix=NULL;

static int list_server_callback_mock(const char *fullpath)
{
	if(list_server_callback_sd)
	{
		char expected_path[256]="";
		snprintf(expected_path, sizeof(expected_path), "%s/%s",
			list_server_callback_fp_prefix,
			list_server_callback_sd[
				list_server_callback_count].timestamp);
		ck_assert_str_eq(expected_path, fullpath);
	}
	else fail_unless(fullpath==NULL);

	list_server_callback_count++;
	return list_server_callback_ret;
}

static void run_test(int expected_init_ret,
	int expected_ret,
	int expected_callback_count,
	enum protocol protocol,
	const char *backup_str,
	const char *regex_str,
	const char *browsedir_str,
	struct sd *s,
	int slen,
	struct sd *fp,
	void setup_asfd_callback(struct asfd *asfd))
{
	struct asfd *asfd;
	struct sdirs *sdirs=NULL;
	sdirs=setup_sdirs(s, slen, protocol);

	asfd=asfd_mock_setup(&reads, &writes);

	setup_asfd_callback(asfd);

	list_server_callback_count=0;
	list_server_callback_sd=fp;
	if(sdirs) list_server_callback_fp_prefix=sdirs->client;
	fail_unless(list_server_init(asfd,
		sdirs,
		NULL /*cntr*/,
		protocol,
		backup_str,
		regex_str,
		browsedir_str)==expected_init_ret);
	if(!expected_init_ret)
		fail_unless(do_list_server_work(
			list_server_callback_mock)==expected_ret);
	list_server_free();
	fail_unless(expected_callback_count==list_server_callback_count);
	tear_down(&asfd, &sdirs);
}

START_TEST(test_do_server_list)
{
	list_server_callback_ret=0;

	// No backups.
	run_test(0,  0, 0, PROTO_1, NULL, NULL, NULL,
		NULL, 0, NULL,
		setup_asfd_no_backups);
	run_test(0,  0, 0, PROTO_2, NULL, NULL, NULL,
		NULL, 0, NULL,
		setup_asfd_no_backups);

	// Backup not specified. burp -a l
	run_test(0, 0, 0, PROTO_1, NULL, NULL, NULL,
		sd1, ARR_LEN(sd1), fp1,
		setup_asfd_1del);
	run_test(0, 0, 0, PROTO_1, NULL, NULL, NULL,
		sd123, ARR_LEN(sd123), fp123,
		setup_asfd_1del_2_3);
	run_test(0, 0, 0, PROTO_2, NULL, NULL, NULL,
		sd1, ARR_LEN(sd1), fp1,
		setup_asfd_1);
	run_test(0, 0, 0, PROTO_2, NULL, NULL, NULL,
		sd123, ARR_LEN(sd123), fp123,
		setup_asfd_1_2_3);
	run_test(0, 0, 0, PROTO_1, "", NULL, NULL,
		sd123, ARR_LEN(sd123), fp123,
		setup_asfd_1del_2_3);
	run_test(0, 0, 0, PROTO_2, "", NULL, NULL,
		sd123, ARR_LEN(sd123), fp123,
		setup_asfd_1_2_3);

	// Have backups, protocol 1. burp -a l -b x
	run_test(0, 0, 1, PROTO_1, "1", NULL, NULL,
		sd1, ARR_LEN(sd1), fp1,
		setup_asfd_1del);
	run_test(0, 0, 1, PROTO_1, "all", NULL, NULL,
		sd1, ARR_LEN(sd1), fp1,
		setup_asfd_1del);
	run_test(0, 0, 1, PROTO_1, "current", NULL, NULL,
		sd1, ARR_LEN(sd1), fp1,
		setup_asfd_1del);
	run_test(0, 0, 1, PROTO_1, "1", NULL, NULL,
		sd123, ARR_LEN(sd123), fp123,
		setup_asfd_1del);
	run_test(0, 0, 1, PROTO_1, "2", NULL, NULL,
		sd123, ARR_LEN(sd123), fp2,
		setup_asfd_2);
	run_test(0, 0, 1, PROTO_1, "3", NULL, NULL,
		sd123, ARR_LEN(sd123), fp3,
		setup_asfd_3);
	run_test(0, 0, 3, PROTO_1, "all", NULL, NULL,
		sd123, ARR_LEN(sd123), fp123,
		setup_asfd_1del_2_3);
	run_test(0, 0, 1, PROTO_1, "current", NULL, NULL,
		sd123, ARR_LEN(sd123), fp3,
		setup_asfd_3);

	// Have backups, protocol 2. burp -a l -b x
	run_test(0, 0, 1, PROTO_2, "1", NULL, NULL,
		sd1, ARR_LEN(sd1), fp1,
		setup_asfd_1);
	run_test(0, 0, 1, PROTO_2, "all", NULL, NULL,
		sd1, ARR_LEN(sd1), fp1,
		setup_asfd_1);
	run_test(0, 0, 1, PROTO_2, "current", NULL, NULL,
		sd1, ARR_LEN(sd1), fp1,
		setup_asfd_1);
	run_test(0, 0, 1, PROTO_2, "1", NULL, NULL,
		sd123, ARR_LEN(sd123), fp1,
		setup_asfd_1);
	run_test(0, 0, 1, PROTO_2, "2", NULL, NULL,
		sd123, ARR_LEN(sd123), fp2,
		setup_asfd_2);
	run_test(0, 0, 1, PROTO_2, "3", NULL, NULL,
		sd123, ARR_LEN(sd123), fp3,
		setup_asfd_3);
	run_test(0, 0, 3, PROTO_2, "all", NULL, NULL,
		sd123, ARR_LEN(sd123), fp123,
		setup_asfd_1_2_3);
	run_test(0, 0, 1, PROTO_2, "current", NULL, NULL,
		sd123, ARR_LEN(sd123), fp3,
		setup_asfd_3);

	// Add regex.
	// burp -a l -r someregex
	run_test(0, 0, 3, PROTO_1, NULL, "someregex", NULL,
		sd123, ARR_LEN(sd123), fp123,
		setup_asfd_1del_2_3);
	run_test(0, 0, 3, PROTO_2, NULL, "someregex", NULL,
		sd123, ARR_LEN(sd123), fp123,
		setup_asfd_1_2_3);
	// burp -a l -b x -r someregex
	run_test(0, 0, 3, PROTO_1, "all", "someregex", NULL,
		sd123, ARR_LEN(sd123), fp123,
		setup_asfd_1del_2_3);
	run_test(0, 0, 1, PROTO_1, "1", "someregex", NULL,
		sd123, ARR_LEN(sd123), fp1,
		setup_asfd_1del);
	run_test(0, 0, 1, PROTO_1, "current", "someregex", NULL,
		sd123, ARR_LEN(sd123), fp3,
		setup_asfd_3);
	run_test(0, 0, 3, PROTO_2, "all", "someregex", NULL,
		sd123, ARR_LEN(sd123), fp123,
		setup_asfd_1_2_3);
	run_test(0, 0, 1, PROTO_2, "1", "someregex", NULL,
		sd123, ARR_LEN(sd123), fp1,
		setup_asfd_1);
	run_test(0, 0, 1, PROTO_2, "current", "someregex", NULL,
		sd123, ARR_LEN(sd123), fp3,
		setup_asfd_3);

	// Add browsedir.
	// burp -a l -d browsedir
	run_test(0, 0, 3, PROTO_1, NULL, NULL, "browsedir",
		sd123, ARR_LEN(sd123), fp123,
		setup_asfd_1del_2_3);
	run_test(0, 0, 3, PROTO_2, NULL, NULL, "browsedir",
		sd123, ARR_LEN(sd123), fp123,
		setup_asfd_1_2_3);
	// burp -a l -b x -d browsedir
	run_test(0, 0, 3, PROTO_1, "all", NULL, "browsedir",
		sd123, ARR_LEN(sd123), fp123,
		setup_asfd_1del_2_3);
	run_test(0, 0, 1, PROTO_1, "1", NULL, "browsedir",
		sd123, ARR_LEN(sd123), fp1,
		setup_asfd_1del);
	run_test(0, 0, 1, PROTO_1, "current", NULL, "browsedir",
		sd123, ARR_LEN(sd123), fp3,
		setup_asfd_3);
	run_test(0, 0, 3, PROTO_2, "all", NULL, "browsedir",
		sd123, ARR_LEN(sd123), fp123,
		setup_asfd_1_2_3);
	run_test(0, 0, 1, PROTO_2, "1", NULL, "browsedir",
		sd123, ARR_LEN(sd123), fp1,
		setup_asfd_1);
	run_test(0, 0, 1, PROTO_2, "current", NULL, "browsedir",
		sd123, ARR_LEN(sd123), fp3,
		setup_asfd_3);

	// Not found. burp -a l -b y
	run_test(0, -1, 0, PROTO_1, "4", NULL, NULL,
		sd123, ARR_LEN(sd123), NULL,
		setup_asfd_not_found);
	run_test(0, -1, 0, PROTO_2, "4", NULL, NULL,
		sd123, ARR_LEN(sd123), NULL,
		setup_asfd_not_found);
	run_test(0, -1, 0, PROTO_1, "0", NULL, NULL,
		sd123, ARR_LEN(sd123), NULL,
		setup_asfd_not_found);
	run_test(0, -1, 0, PROTO_2, "0", NULL, NULL,
		sd123, ARR_LEN(sd123), NULL,
		setup_asfd_not_found);
	run_test(0, -1, 0, PROTO_1, "junk", NULL, NULL,
		sd123, ARR_LEN(sd123), NULL,
		setup_asfd_not_found);
	run_test(0, -1, 0, PROTO_2, "junk", NULL, NULL,
		sd123, ARR_LEN(sd123), NULL,
		setup_asfd_not_found);
	run_test(0, -1, 0, PROTO_1, "-1", NULL, NULL,
		sd123, ARR_LEN(sd123), NULL,
		setup_asfd_not_found);
	run_test(0, -1, 0, PROTO_2, "-1", NULL, NULL,
		sd123, ARR_LEN(sd123), NULL,
		setup_asfd_not_found);

	// Error from the list_server_callback.
	list_server_callback_ret=-1;
	run_test(0, -1, 1, PROTO_1, "1", NULL, NULL,
		sd1, ARR_LEN(sd1), fp1,
		setup_asfd_1del);
	run_test(0, -1, 1, PROTO_1, "all", NULL, NULL,
		sd1, ARR_LEN(sd1), fp1,
		setup_asfd_1del);
	run_test(0, -1, 1, PROTO_2, "1", NULL, NULL,
		sd1, ARR_LEN(sd1), fp1,
		setup_asfd_1);
	run_test(0, -1, 1, PROTO_2, "all", NULL, NULL,
		sd1, ARR_LEN(sd1), fp1,
		setup_asfd_1);

	// Write failure.
	run_test(0, -1, 0, PROTO_1, NULL, NULL, NULL,
		sd1, ARR_LEN(sd1), NULL,
		setup_asfd_1del_write_failure);
	run_test(0, -1, 0, PROTO_1, "1", NULL, NULL,
		sd1, ARR_LEN(sd1), NULL,
		setup_asfd_1del_write_failure);
	run_test(0, -1, 0, PROTO_1, "all", NULL, NULL,
		sd1, ARR_LEN(sd1), NULL,
		setup_asfd_1del_write_failure);

	// Bad regex.
	// burp -a l -b x -r '*'
	run_test(-1, 0, 0, PROTO_1, "1", "*", NULL,
		sd123, ARR_LEN(sd123), NULL,
		setup_asfd_bad_regex);
}
END_TEST

static void run_check_browsedir(const char *browsedir,
	struct sbuf *mb,
	enum cmd cmd,
	const char *path,
	char **last_bd_match,
	const char *expected_last_bd_match,
	int expected_ret,
	int expected_isdir)
{
	char *mbpath;
	size_t bdlen=0;
	if(browsedir) bdlen=strlen(browsedir);
	fail_unless((mbpath=strdup_w(path, __func__))!=NULL);
	iobuf_from_str(&mb->path, cmd, mbpath);
	fail_unless(check_browsedir(
		browsedir,
		mb,
		bdlen,
		last_bd_match)
			==expected_ret);
	if(expected_last_bd_match)
	{
		fail_unless(*last_bd_match!=NULL);
		ck_assert_str_eq(expected_last_bd_match, *last_bd_match);
	}
	else
		fail_unless(*last_bd_match==NULL);
	fail_unless(expected_isdir==S_ISDIR(mb->statp.st_mode));
	sbuf_free_content(mb);
}

static void do_test_check_browsedir(enum protocol protocol)
{
	struct sbuf *mb;
	const char *browsedir;
	char *last_bd_match=NULL;

	fail_unless((mb=sbuf_alloc(protocol))!=NULL);

	browsedir="/path";
	run_check_browsedir(browsedir, mb, CMD_FILE, "/aaaa/path/file",
		&last_bd_match, NULL, 0, 0);
	run_check_browsedir(browsedir, mb, CMD_FILE, "/pat/aaa/file",
		&last_bd_match, NULL, 0, 0);
	run_check_browsedir(browsedir, mb, CMD_DIRECTORY, "/path",
		&last_bd_match, ".",  1, 1);
	run_check_browsedir(browsedir, mb, CMD_DIRECTORY, "/path/",
		&last_bd_match, ".",  0, 1);
	run_check_browsedir(browsedir, mb, CMD_FILE, "/path/aa/file",
		&last_bd_match, "aa", 1, 1);
	// Get a bit more coverage by setting the statp mode to S_IFDIR.
	mb->statp.st_mode &= ~(S_IFMT);
	mb->statp.st_mode |= S_IFDIR;
	run_check_browsedir(browsedir, mb, CMD_FILE, "/path/to/file",
		&last_bd_match, "to", 1, 1);
	run_check_browsedir(browsedir, mb, CMD_FILE, "/path/to/gggg",
		&last_bd_match, "to", 0, 1);
	run_check_browsedir(browsedir, mb, CMD_FILE, "/path/to/gggg/zzz",
		&last_bd_match, "to", 0, 1);
	run_check_browsedir(browsedir, mb, CMD_FILE, "/path/to/hhhh",
		&last_bd_match, "to", 0, 1);
	run_check_browsedir(browsedir, mb, CMD_FILE, "/path/so/hhhh",
		&last_bd_match, "so", 1, 1);
	run_check_browsedir(browsedir, mb, CMD_FILE, "/patha/aaa/file",
		&last_bd_match, "so", 0, 0);
	run_check_browsedir(browsedir, mb, CMD_FILE, "path/aaa/file",
		&last_bd_match, "so", 0, 0);

	sbuf_free(&mb);
	free_w(&last_bd_match);
	alloc_check();
}

START_TEST(test_check_browsedir)
{
	do_test_check_browsedir(PROTO_1);
	do_test_check_browsedir(PROTO_2);
}
END_TEST

static void do_test_check_browsedir_root(enum protocol protocol)
{
	struct sbuf *mb;
	const char *browsedir;
	char *last_bd_match=NULL;

	fail_unless((mb=sbuf_alloc(protocol))!=NULL);

	browsedir="/";
	run_check_browsedir(browsedir, mb, CMD_FILE, "aaa",
		&last_bd_match, NULL,  0, 0);
	run_check_browsedir(browsedir, mb, CMD_DIRECTORY, "/",
		&last_bd_match, ".",   1, 1);
	run_check_browsedir(browsedir, mb, CMD_DIRECTORY, "/aa",
		&last_bd_match, "aa",  1, 1);
	run_check_browsedir(browsedir, mb, CMD_FILE, "/aa/bb",
		&last_bd_match, "aa",  0, 1);

	sbuf_free(&mb);
	free_w(&last_bd_match);
	alloc_check();
}

START_TEST(test_check_browsedir_root)
{
	do_test_check_browsedir_root(PROTO_1);
	do_test_check_browsedir_root(PROTO_2);
}
END_TEST

static void do_test_check_browsedir_null_or_blank(enum protocol protocol,
	const char *browsedir)
{
	struct sbuf *mb;
	char *last_bd_match=NULL;

	fail_unless((mb=sbuf_alloc(protocol))!=NULL);

	run_check_browsedir(browsedir, mb, CMD_FILE, "aaa",
		&last_bd_match, "aaa",  1, 0);
	run_check_browsedir(browsedir, mb, CMD_DIRECTORY, "/",
		&last_bd_match, "/",    1, 1);
	run_check_browsedir(browsedir, mb, CMD_DIRECTORY, "/asdf",
		&last_bd_match, "/",    0, 1);
	run_check_browsedir(browsedir, mb, CMD_DIRECTORY, "/asdf/blah",
		&last_bd_match, "/",    0, 1);
	run_check_browsedir(browsedir, mb, CMD_FILE, "zzz",
		&last_bd_match, "zzz",  1, 0);
	run_check_browsedir(browsedir, mb, CMD_FILE, "zzzz//",
		&last_bd_match, "zzzz",  1, 1);

	sbuf_free(&mb);
	free_w(&last_bd_match);
	alloc_check();
}

START_TEST(test_check_browsedir_null_or_blank)
{
	do_test_check_browsedir_null_or_blank(PROTO_1, NULL);
	do_test_check_browsedir_null_or_blank(PROTO_2, NULL);
	do_test_check_browsedir_null_or_blank(PROTO_1, "");
	do_test_check_browsedir_null_or_blank(PROTO_2, "");
}
END_TEST

static void do_test_check_browsedir_windows(enum protocol protocol)
{
	struct sbuf *mb;
	const char *browsedir;
	char *last_bd_match=NULL;

	fail_unless((mb=sbuf_alloc(protocol))!=NULL);

	browsedir="C:/aaa";
	run_check_browsedir(browsedir, mb, CMD_FILE, "A:/aaa",
		&last_bd_match, NULL,   0, 0);
	run_check_browsedir(browsedir, mb, CMD_DIRECTORY, "C:/aaa",
		&last_bd_match, ".",    1, 1);
	run_check_browsedir(browsedir, mb, CMD_FILE, "C:/aaa/file",
		&last_bd_match, "file", 1, 0);
	run_check_browsedir(browsedir, mb, CMD_FILE, "C:/aaa/filx",
		&last_bd_match, "filx", 1, 0);
	run_check_browsedir(browsedir, mb, CMD_FILE, "D:/adf",
		&last_bd_match, "filx", 0, 0);

	sbuf_free(&mb);
	free_w(&last_bd_match);
	alloc_check();
}

START_TEST(test_check_browsedir_windows)
{
	do_test_check_browsedir_windows(PROTO_1);
	do_test_check_browsedir_windows(PROTO_2);
}
END_TEST

static void do_test_check_browsedir_windows_blank(enum protocol protocol)
{
	struct sbuf *mb;
	const char *browsedir;
	char *last_bd_match=NULL;

	fail_unless((mb=sbuf_alloc(protocol))!=NULL);

	browsedir="";
	run_check_browsedir(browsedir, mb, CMD_FILE, "A:/aaa",
		&last_bd_match, "A:", 1, 1);
	run_check_browsedir(browsedir, mb, CMD_DIRECTORY, "C:/aaa",
		&last_bd_match, "C:", 1, 1);
	run_check_browsedir(browsedir, mb, CMD_FILE, "C:/aaa/file",
		&last_bd_match, "C:", 0, 1);
	run_check_browsedir(browsedir, mb, CMD_FILE, "C:/aaa/filx",
		&last_bd_match, "C:", 0, 1);
	run_check_browsedir(browsedir, mb, CMD_FILE, "D:/adf",
		&last_bd_match, "D:", 1, 1);

	sbuf_free(&mb);
	free_w(&last_bd_match);
	alloc_check();
}

START_TEST(test_check_browsedir_windows_blank)
{
	do_test_check_browsedir_windows_blank(PROTO_1);
	do_test_check_browsedir_windows_blank(PROTO_2);
}
END_TEST

START_TEST(test_check_browsedir_alloc_error)
{
	char *path;
	size_t bdlen;
	struct sbuf *mb;
	const char *browsedir;
	char *last_bd_match=NULL;

	fail_unless((mb=sbuf_alloc(PROTO_1))!=NULL);

	browsedir="";
	bdlen=0;
	fail_unless((path=strdup_w("aaa", __func__))!=NULL);
	iobuf_from_str(&mb->path, CMD_FILE, path);
	alloc_errors=1;
	fail_unless(check_browsedir(
		browsedir,
		mb,
		bdlen,
		&last_bd_match)
			==-1);

	sbuf_free(&mb);
	free_w(&last_bd_match);
	alloc_check();
}
END_TEST

START_TEST(test_maybe_fake_directory)
{
	char *attr;
	struct sbuf *mb;
	fail_unless((mb=sbuf_alloc(PROTO_1))!=NULL);
	fail_unless((attr=strdup_w("120398102938", __func__))!=NULL);
	iobuf_set(&mb->attr, CMD_ATTRIBS, attr, strlen(attr));

	// Check that it does not explode on re-encoding attribs that are
	// longer than the buffer we just allocated.
	maybe_fake_directory(mb);

	sbuf_free(&mb);
	alloc_check();
}
END_TEST

Suite *suite_server_list(void)
{
	Suite *s;
	TCase *tc_core;

	s=suite_create("server_list");

	tc_core=tcase_create("Core");
	tcase_set_timeout(tc_core, 60);

	tcase_add_test(tc_core, test_do_server_list);
	tcase_add_test(tc_core, test_check_browsedir);
	tcase_add_test(tc_core, test_check_browsedir_root);
	tcase_add_test(tc_core, test_check_browsedir_null_or_blank);
	tcase_add_test(tc_core, test_check_browsedir_windows);
	tcase_add_test(tc_core, test_check_browsedir_windows_blank);
	tcase_add_test(tc_core, test_check_browsedir_alloc_error);
	tcase_add_test(tc_core, test_maybe_fake_directory);

	suite_add_tcase(s, tc_core);

	return s;
}
