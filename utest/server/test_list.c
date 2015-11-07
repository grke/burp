#include "../test.h"
#include "../../src/alloc.h"
#include "../../src/asfd.h"
#include "../../src/bu.h"
#include "../../src/fsops.h"
#include "../../src/server/bu_get.h"
#include "../../src/server/list.h"
#include "../../src/server/sdirs.h"
#include "../../src/iobuf.h"
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

static void setup_asfd_bu_failure(void)
{
}

static void setup_asfd_1del(void)
{
	int w=0;
	asfd_mock_write(&w, 0,
		CMD_TIMESTAMP, "0000001 1970-01-01 00:00:00 (deletable)");
}

static void setup_asfd_1(void)
{
	int w=0;
	asfd_mock_write(&w, 0,
		CMD_TIMESTAMP, "0000001 1970-01-01 00:00:00");
}

static void setup_asfd_2(void)
{
	int w=0;
	asfd_mock_write(&w, 0,
		CMD_TIMESTAMP, "0000002 1970-01-02 00:00:00");
}

static void setup_asfd_3(void)
{
	int w=0;
	asfd_mock_write(&w, 0,
		CMD_TIMESTAMP, "0000003 1970-01-03 00:00:00");
}

static void setup_asfd_1del_2_3(void)
{
	int w=0;
	asfd_mock_write(&w, 0,
		CMD_TIMESTAMP, "0000001 1970-01-01 00:00:00 (deletable)");
	asfd_mock_write(&w, 0,
		CMD_TIMESTAMP, "0000002 1970-01-02 00:00:00");
	asfd_mock_write(&w, 0,
		CMD_TIMESTAMP, "0000003 1970-01-03 00:00:00");
}

static void setup_asfd_1_2_3(void)
{
	int w=0;
	asfd_mock_write(&w, 0,
		CMD_TIMESTAMP, "0000001 1970-01-01 00:00:00");
	asfd_mock_write(&w, 0,
		CMD_TIMESTAMP, "0000002 1970-01-02 00:00:00");
	asfd_mock_write(&w, 0,
		CMD_TIMESTAMP, "0000003 1970-01-03 00:00:00");
}

static void setup_asfd_not_found(void)
{
	int w=0;
	asfd_mock_write(&w, 0, CMD_ERROR, "backup not found");
}

static void setup_asfd_1del_write_failure(void)
{
	int w=0;
	asfd_mock_write(&w, -1,
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
	struct sd *s,
	int slen,
	struct sd *fp,
	void setup_asfd_callback(void))
{
	struct asfd *asfd;
	struct sdirs *sdirs=NULL;
	if(slen) sdirs=setup_sdirs(s, slen, protocol);

	asfd=asfd_mock_setup(&reads, &writes, 10, 10);

	setup_asfd_callback();

	list_server_callback_count=0;
	list_server_callback_sd=fp;
	if(sdirs) list_server_callback_fp_prefix=sdirs->client;
	fail_unless(list_server_init(asfd,
		sdirs,
		NULL /*cntr*/,
		protocol,
		backup_str,
		regex_str,
		NULL /*browsedir*/)==expected_init_ret);
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
	run_test(-1, 0, 0, PROTO_1, NULL, NULL,
		NULL, 0, NULL,
		setup_asfd_bu_failure);
	run_test(-1, 0, 0, PROTO_2, NULL, NULL,
		NULL, 0, NULL,
		setup_asfd_bu_failure);

	// Backup not specified. burp -a l
	run_test(0, 0, 0, PROTO_1, NULL, NULL,
		sd1, ARR_LEN(sd1), fp1,
		setup_asfd_1del);
	run_test(0, 0, 0, PROTO_1, NULL, NULL,
		sd123, ARR_LEN(sd123), fp123,
		setup_asfd_1del_2_3);
	run_test(0, 0, 0, PROTO_2, NULL, NULL,
		sd1, ARR_LEN(sd1), fp1,
		setup_asfd_1);
	run_test(0, 0, 0, PROTO_2, NULL, NULL,
		sd123, ARR_LEN(sd123), fp123,
		setup_asfd_1_2_3);

	// Have backups, protocol 1. burp -a l -b x
	run_test(0, 0, 1, PROTO_1, "1", NULL,
		sd1, ARR_LEN(sd1), fp1,
		setup_asfd_1del);
	run_test(0, 0, 1, PROTO_1, "all", NULL,
		sd1, ARR_LEN(sd1), fp1,
		setup_asfd_1del);
	run_test(0, 0, 1, PROTO_1, "current", NULL,
		sd1, ARR_LEN(sd1), fp1,
		setup_asfd_1del);
	run_test(0, 0, 1, PROTO_1, "1", NULL,
		sd123, ARR_LEN(sd123), fp123,
		setup_asfd_1del);
	run_test(0, 0, 1, PROTO_1, "2", NULL,
		sd123, ARR_LEN(sd123), fp2,
		setup_asfd_2);
	run_test(0, 0, 1, PROTO_1, "3", NULL,
		sd123, ARR_LEN(sd123), fp3,
		setup_asfd_3);
	run_test(0, 0, 3, PROTO_1, "all", NULL,
		sd123, ARR_LEN(sd123), fp123,
		setup_asfd_1del_2_3);
	run_test(0, 0, 1, PROTO_1, "current", NULL,
		sd123, ARR_LEN(sd123), fp3,
		setup_asfd_3);

	// Have backups, protocol 2. burp -a l -b x
	run_test(0, 0, 1, PROTO_2, "1", NULL,
		sd1, ARR_LEN(sd1), fp1,
		setup_asfd_1);
	run_test(0, 0, 1, PROTO_2, "all", NULL,
		sd1, ARR_LEN(sd1), fp1,
		setup_asfd_1);
	run_test(0, 0, 1, PROTO_2, "current", NULL,
		sd1, ARR_LEN(sd1), fp1,
		setup_asfd_1);
	run_test(0, 0, 1, PROTO_2, "1", NULL,
		sd123, ARR_LEN(sd123), fp1,
		setup_asfd_1);
	run_test(0, 0, 1, PROTO_2, "2", NULL,
		sd123, ARR_LEN(sd123), fp2,
		setup_asfd_2);
	run_test(0, 0, 1, PROTO_2, "3", NULL,
		sd123, ARR_LEN(sd123), fp3,
		setup_asfd_3);
	run_test(0, 0, 3, PROTO_2, "all", NULL,
		sd123, ARR_LEN(sd123), fp123,
		setup_asfd_1_2_3);
	run_test(0, 0, 1, PROTO_2, "current", NULL,
		sd123, ARR_LEN(sd123), fp3,
		setup_asfd_3);

	// Add regex.
	// burp -a l -r someregex
	run_test(0, 0, 3, PROTO_1, NULL, "someregex",
		sd123, ARR_LEN(sd123), fp123,
		setup_asfd_1del_2_3);
	run_test(0, 0, 3, PROTO_2, NULL, "someregex",
		sd123, ARR_LEN(sd123), fp123,
		setup_asfd_1_2_3);
	// burp -a l -b x -r someregex
	run_test(0, 0, 3, PROTO_1, "all", "someregex",
		sd123, ARR_LEN(sd123), fp123,
		setup_asfd_1del_2_3);
	run_test(0, 0, 1, PROTO_1, "1", "someregex",
		sd123, ARR_LEN(sd123), fp1,
		setup_asfd_1del);
	run_test(0, 0, 1, PROTO_1, "current", "someregex",
		sd123, ARR_LEN(sd123), fp3,
		setup_asfd_3);
	run_test(0, 0, 3, PROTO_2, "all", "someregex",
		sd123, ARR_LEN(sd123), fp123,
		setup_asfd_1_2_3);
	run_test(0, 0, 1, PROTO_2, "1", "someregex",
		sd123, ARR_LEN(sd123), fp1,
		setup_asfd_1);
	run_test(0, 0, 1, PROTO_2, "current", "someregex",
		sd123, ARR_LEN(sd123), fp3,
		setup_asfd_3);

	// Not found. burp -a l -b y
	run_test(0, -1, 0, PROTO_1, "4", NULL,
		sd123, ARR_LEN(sd123), NULL,
		setup_asfd_not_found);
	run_test(0, -1, 0, PROTO_2, "4", NULL,
		sd123, ARR_LEN(sd123), NULL,
		setup_asfd_not_found);
	run_test(0, -1, 0, PROTO_1, "0", NULL,
		sd123, ARR_LEN(sd123), NULL,
		setup_asfd_not_found);
	run_test(0, -1, 0, PROTO_2, "0", NULL,
		sd123, ARR_LEN(sd123), NULL,
		setup_asfd_not_found);
	run_test(0, -1, 0, PROTO_1, "junk", NULL,
		sd123, ARR_LEN(sd123), NULL,
		setup_asfd_not_found);
	run_test(0, -1, 0, PROTO_2, "junk", NULL,
		sd123, ARR_LEN(sd123), NULL,
		setup_asfd_not_found);
	run_test(0, -1, 0, PROTO_1, "-1", NULL,
		sd123, ARR_LEN(sd123), NULL,
		setup_asfd_not_found);
	run_test(0, -1, 0, PROTO_2, "-1", NULL,
		sd123, ARR_LEN(sd123), NULL,
		setup_asfd_not_found);
	run_test(0, -1, 0, PROTO_1, "", NULL,
		sd123, ARR_LEN(sd123), NULL,
		setup_asfd_not_found);
	run_test(0, -1, 0, PROTO_2, "", NULL,
		sd123, ARR_LEN(sd123), NULL,
		setup_asfd_not_found);

	// Error from the list_server_callback.
	list_server_callback_ret=-1;
	run_test(0, -1, 1, PROTO_1, "1", NULL,
		sd1, ARR_LEN(sd1), fp1,
		setup_asfd_1del);
	run_test(0, -1, 1, PROTO_1, "all", NULL,
		sd1, ARR_LEN(sd1), fp1,
		setup_asfd_1del);
	run_test(0, -1, 1, PROTO_2, "1", NULL,
		sd1, ARR_LEN(sd1), fp1,
		setup_asfd_1);
	run_test(0, -1, 1, PROTO_2, "all", NULL,
		sd1, ARR_LEN(sd1), fp1,
		setup_asfd_1);

	// Write failure.
	run_test(0, -1, 0, PROTO_1, NULL, NULL,
		sd1, ARR_LEN(sd1), NULL,
		setup_asfd_1del_write_failure);
	run_test(0, -1, 0, PROTO_1, "1", NULL,
		sd1, ARR_LEN(sd1), NULL,
		setup_asfd_1del_write_failure);
	run_test(0, -1, 0, PROTO_1, "all", NULL,
		sd1, ARR_LEN(sd1), NULL,
		setup_asfd_1del_write_failure);

	// Bad regex.
	// burp -a l -b x -r '*'
	run_test(-1, 0, 0, PROTO_1, "1", "*",
		sd123, ARR_LEN(sd123), NULL,
		setup_asfd_1);
}
END_TEST

Suite *suite_server_list(void)
{
	Suite *s;
	TCase *tc_core;

	s=suite_create("server_list");

	tc_core=tcase_create("Core");

	tcase_add_test(tc_core, test_do_server_list);
	suite_add_tcase(s, tc_core);

	return s;
}
