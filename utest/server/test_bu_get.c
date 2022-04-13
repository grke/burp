#include "../test.h"
#include "../builders/build.h"
#include "../../src/alloc.h"
#include "../../src/bu.h"
#include "../../src/conf.h"
#include "../../src/conffile.h"
#include "../../src/cstat.h"
#include "../../src/fsops.h"
#include "../../src/lock.h"
#include "../../src/prepend.h"
#include "../../src/server/bu_get.h"
#include "../../src/server/protocol1/fdirs.h"
#include "../../src/server/sdirs.h"
#include "../../src/server/timestamp.h"

#define BASE		"utest_bu_get"

static struct sdirs *setup(void)
{
	struct sdirs *sdirs;
	fail_unless(recursive_delete(BASE)==0);
	fail_unless((sdirs=sdirs_alloc())!=NULL);
	return sdirs;
}

static void tear_down(struct sdirs **sdirs)
{
	sdirs_free(sdirs);
	fail_unless(recursive_delete(BASE)==0);
	alloc_check();
}

static void do_sdirs_init(struct sdirs *sdirs)
{
	fail_unless(!sdirs_init(sdirs,
		BASE, // directory
		"utestclient", // cname
		NULL, // client_lockdir
		"a_group", // dedup_group
		NULL // manual_delete
		));
}

static void do_assert_bu_list(struct bu *bu_list,
	struct sd *s, unsigned int len)
{
	unsigned int count=0;
	struct bu *bu;
	struct bu *last;

	bu=bu_list;
	last=NULL;
	for(count=0; count<len; count++)
	{
		fail_unless(bu!=NULL);

		fail_unless(s[count].bno==bu->bno);
		fail_unless(s[count].index==bu->index);
		fail_unless(s[count].flags==bu->flags);
		ck_assert_str_eq(s[count].timestamp, bu->timestamp);

		// Check reverse linkage.
		fail_unless(last==bu->prev);

		last=bu;
		bu=bu->next;
	}
	fail_unless(len==count);
	fail_unless(bu==NULL);
}

void assert_bu_list(struct sdirs *sdirs, struct sd *s, unsigned int len)
{
	struct bu *bu_list=NULL;
	fail_unless(!bu_get_list(sdirs, &bu_list));
	do_assert_bu_list(bu_list, s, len);
	bu_list_free(&bu_list);
}

static void build_and_check(struct sd *s, int slen,
	struct sd *e, int elen)
{
	struct sdirs *sdirs=setup();
	do_sdirs_init(sdirs);
	build_storage_dirs(sdirs, s, slen);
	assert_bu_list(sdirs, e, elen);
	tear_down(&sdirs);
}

static struct sd sd1[] = {
	{ "0000005 1970-01-05 00:00:00", 5, 1, BU_CURRENT|BU_DELETABLE }
};

static struct sd sd2[] = {
	{ "0000001 1970-01-01 00:00:00", 1, 1, BU_DELETABLE },
	{ "0000005 1970-01-05 00:00:00", 5, 2, BU_CURRENT }
};

static struct sd sd3[] = {
	{ "0000001 1970-01-01 00:00:00", 1, 1, BU_DELETABLE },
	{ "0000003 1970-01-03 00:00:00", 3, 2, 0 },
	{ "0000005 1970-01-05 00:00:00", 5, 3, BU_CURRENT }
};

static struct sd sd4[] = {
	{ "0000001 1970-01-01 00:00:00", 1, 1, BU_DELETABLE },
	{ "0000002 1970-01-02 00:00:00", 2, 2, 0 },
	{ "0000003 1970-01-03 00:00:00", 3, 3, 0 },
	{ "0000004 1970-01-04 00:00:00", 4, 4, 0 },
	{ "0000005 1970-01-05 00:00:00", 5, 5, BU_CURRENT }
};

static struct sd sd5[] = {
	{ "0000001 1970-01-01 00:00:00", 1, 1, BU_DELETABLE },
	{ "0000002 1970-01-02 00:00:00", 2, 2, 0 },
	{ "0000003 1970-01-03 00:00:00", 3, 3, BU_HARDLINKED },
	{ "0000004 1970-01-04 00:00:00", 4, 4, BU_DELETABLE },
	{ "0000005 1970-01-05 00:00:00", 5, 5, BU_CURRENT }
};

static struct sd sd6[] = {
	{ "0000001 1970-01-01 00:00:00", 1, 1, BU_HARDLINKED|BU_DELETABLE },
	{ "0000002 1970-01-02 00:00:00", 2, 2, BU_HARDLINKED|BU_DELETABLE },
	{ "0000005 1970-01-05 00:00:00", 5, 3, BU_HARDLINKED|BU_DELETABLE|BU_CURRENT }
};

static struct sd sd7[] = {
	{ "0000001 1970-01-01 00:00:00", 1,  1, BU_HARDLINKED|BU_DELETABLE },
	{ "0000005 1970-01-05 00:00:00", 5,  2, BU_HARDLINKED|BU_DELETABLE },
	{ "0000010 1970-01-10 00:00:00", 10, 3, BU_HARDLINKED|BU_DELETABLE },
	{ "0000020 1970-01-20 00:00:00", 20, 4, BU_DELETABLE },
	{ "0000021 1970-01-21 00:00:00", 21, 5, 0 },
	{ "0000022 1970-01-22 00:00:00", 22, 6, 0 },
	{ "0000023 1970-01-23 00:00:00", 23, 7, BU_CURRENT }
};

static struct sd sd8[] = {
	{ "0000010 1970-01-01 00:00:00", 10, 1, BU_HARDLINKED|BU_DELETABLE },
	{ "0000015 1970-01-05 00:00:00", 15, 2, BU_HARDLINKED|BU_DELETABLE },
	{ "0000020 1970-01-10 00:00:00", 20, 3, BU_HARDLINKED|BU_DELETABLE },
	{ "0000030 1970-01-20 00:00:00", 30, 4, BU_DELETABLE },
	{ "0000031 1970-01-21 00:00:00", 31, 5, 0 },
	{ "0000032 1970-01-22 00:00:00", 32, 6, 0 },
	{ "0000033 1970-01-23 00:00:00", 33, 7, BU_CURRENT }
};

static struct sd sd9[] = {
	{ "0000001 1970-01-01 00:00:00", 1, 1, BU_DELETABLE },
	{ "0000002 1970-01-02 00:00:00", 2, 2, 0 },
	{ "0000003 1970-01-03 00:00:00", 3, 3, 0 },
	{ "0000004 1970-01-04 00:00:00", 4, 4, 0 },
	{ "0000005 1970-01-05 00:00:00", 5, 5, BU_CURRENT },
	{ "0000006 1970-01-06 00:00:00", 6, 6, BU_WORKING }
};

static struct sd sd10[] = {
	{ "0000001 1970-01-01 00:00:00", 1, 1, BU_DELETABLE },
	{ "0000002 1970-01-02 00:00:00", 2, 2, 0 },
	{ "0000003 1970-01-03 00:00:00", 3, 3, 0 },
	{ "0000004 1970-01-04 00:00:00", 4, 4, 0 },
	{ "0000005 1970-01-05 00:00:00", 5, 5, BU_CURRENT },
	{ "0000006 1970-01-06 00:00:00", 6, 6, BU_FINISHING }
};

static struct sd sd11[] = {
	{ "0000005 1970-01-01 00:00:00", 5, 1, BU_DELETABLE|BU_MANIFEST },
	{ "0000006 1970-01-02 00:00:00", 6, 2, BU_MANIFEST },
	{ "0000007 1970-01-03 00:00:00", 7, 3, BU_MANIFEST },
	{ "0000008 1970-01-04 00:00:00", 8, 4, BU_MANIFEST },
	{ "0000009 1970-01-05 00:00:00", 9, 5, BU_MANIFEST|BU_CURRENT },
};

static struct sd sd12[] = {
	{ "0000005 1970-01-01 00:00:00", 5, 1,
		BU_MANIFEST|BU_LOG_BACKUP|BU_DELETABLE },
	{ "0000006 1970-01-02 00:00:00", 6, 2,
		BU_MANIFEST|BU_LOG_BACKUP|BU_LOG_RESTORE },
	{ "0000007 1970-01-03 00:00:00", 7, 3,
		BU_MANIFEST|BU_LOG_BACKUP|BU_LOG_VERIFY|BU_LOG_RESTORE },
	{ "0000008 1970-01-04 00:00:00", 8, 4,
		BU_MANIFEST|BU_LOG_BACKUP },
	{ "0000009 1970-01-05 00:00:00", 9, 5,
		BU_MANIFEST|BU_LOG_BACKUP|BU_LOG_VERIFY|BU_CURRENT },
};

static void build_and_check_same(struct sd *s, int len)
{
	build_and_check(s, len, s, len);
}

static void do_tests()
{
	build_and_check_same(sd1, ARR_LEN(sd1));
	build_and_check_same(sd2, ARR_LEN(sd2));
	build_and_check_same(sd3, ARR_LEN(sd3));
	build_and_check_same(sd4, ARR_LEN(sd4));
	build_and_check_same(sd5, ARR_LEN(sd5));
	build_and_check_same(sd6, ARR_LEN(sd6));
	build_and_check_same(sd7, ARR_LEN(sd7));
	build_and_check_same(sd8, ARR_LEN(sd8));
	// These two should not have working/finishing loaded.
	build_and_check(sd9, ARR_LEN(sd9), sd4, ARR_LEN(sd4));
	build_and_check(sd10, ARR_LEN(sd10), sd4, ARR_LEN(sd4));
	build_and_check_same(sd11, ARR_LEN(sd11));
	// This should not have the log stuff loaded.
	build_and_check(sd12, ARR_LEN(sd12), sd11, ARR_LEN(sd11));
}

START_TEST(test_bu_get_proto_1)
{
	do_tests();
}
END_TEST

static enum run_status run_status=RUN_STATUS_IDLE;
static enum cntr_status cntr_status=CNTR_STATUS_UNSET;

static void assert_bu_list_with_working(struct sdirs *sdirs,
	struct sd *s, unsigned int len)
{
	struct bu *bu_list=NULL;
	struct cntr cntr;
	memset(&cntr, 0, sizeof(cntr));
	cntr.cntr_status=cntr_status;
	fail_unless(!bu_get_list_with_working(sdirs, &bu_list));
	do_assert_bu_list(bu_list, s, len);
	bu_list_free(&bu_list);
}

static int compressed_logs=0;

static void build_and_check_working(struct sd *s, int slen,
	struct sd *e, int elen)
{
	struct sdirs *sdirs=setup();
	do_sdirs_init(sdirs);
	if(compressed_logs)
		build_storage_dirs_compressed_logs(sdirs, s, slen);
	else
		build_storage_dirs(sdirs, s, slen);
	assert_bu_list_with_working(sdirs, e, elen);
	tear_down(&sdirs);
}

static void build_and_check_working_same(struct sd *s, int len)
{
	build_and_check_working(s, len, s, len);
}

static void do_tests_with_working()
{
	build_and_check_working_same(sd1, ARR_LEN(sd1));
	build_and_check_working_same(sd2, ARR_LEN(sd2));
	build_and_check_working_same(sd3, ARR_LEN(sd3));
	build_and_check_working_same(sd4, ARR_LEN(sd4));
	build_and_check_working_same(sd5, ARR_LEN(sd5));
	build_and_check_working_same(sd6, ARR_LEN(sd6));
	build_and_check_working_same(sd7, ARR_LEN(sd7));
	build_and_check_working_same(sd8, ARR_LEN(sd8));
	build_and_check_working_same(sd9, ARR_LEN(sd9));
	build_and_check_working_same(sd10, ARR_LEN(sd10));
	build_and_check_working_same(sd11, ARR_LEN(sd11));
	build_and_check_working_same(sd12, ARR_LEN(sd12));
}

START_TEST(test_bu_get_with_working_proto_1)
{
	run_status=RUN_STATUS_IDLE;
	cntr_status=CNTR_STATUS_UNSET;
	compressed_logs=0;
	do_tests_with_working();
	compressed_logs=1;
	do_tests_with_working();
}
END_TEST

static struct sd rn1[] = {
	{ "0000001 1970-01-01 00:00:00", 1, 1, BU_DELETABLE },
	{ "0000003 1970-01-03 00:00:00", 3, 2, },
	{ "0000005 1970-01-05 00:00:00", 5, 3, BU_CURRENT }
};
static struct sd rn2[] = {
	{ "0000001 1970-01-01 00:00:00", 1, 1, BU_DELETABLE },
	{ "0000003 1970-01-03 00:00:00", 3, 2, },
	{ "0000005 1970-01-05 00:00:00", 5, 3, BU_CURRENT }
};
static struct sd rn3[] = {
	{ "0000001 1970-01-01 00:00:00", 1, 1, BU_DELETABLE },
	{ "0000003 1970-01-03 00:00:00", 3, 2, },
	{ "0000005 1970-01-05 00:00:00", 5, 3, BU_CURRENT }
};

static void do_tests_with_running()
{
	run_status=RUN_STATUS_RUNNING;
	cntr_status=CNTR_STATUS_UNSET;
	build_and_check_working_same(sd3, ARR_LEN(sd3));
	cntr_status=CNTR_STATUS_SCANNING;
	build_and_check_working_same(rn1, ARR_LEN(rn1));
	cntr_status=CNTR_STATUS_RESTORING;
	build_and_check_working_same(rn2, ARR_LEN(rn2));
	cntr_status=CNTR_STATUS_VERIFYING;
	build_and_check_working_same(rn3, ARR_LEN(rn3));
}

START_TEST(test_bu_get_with_running_proto_1)
{
	do_tests_with_running();
}
END_TEST

static void assert_bu_list_current(struct sdirs *sdirs,
	struct sd *s, unsigned int len)
{
	struct bu *bu_list=NULL;
	fail_unless(!bu_get_current(sdirs, &bu_list));
	do_assert_bu_list(bu_list, s, len);
	bu_list_free(&bu_list);
}

static void build_and_check_current(struct sd *s, int slen,
	struct sd *e, int elen)
{
	struct sdirs *sdirs=setup();
	do_sdirs_init(sdirs);
	build_storage_dirs(sdirs, s, slen);
	assert_bu_list_current(sdirs, e, elen);
	tear_down(&sdirs);
}

static struct sd c1[] = {
	{ "0000005 1970-01-05 00:00:00", 5, 0, BU_CURRENT }
};

static void do_tests_current()
{
	build_and_check_current(sd1, ARR_LEN(sd1), c1, ARR_LEN(c1));
	build_and_check_current(sd2, ARR_LEN(sd2), c1, ARR_LEN(c1));
	build_and_check_current(sd3, ARR_LEN(sd3), c1, ARR_LEN(c1));
	build_and_check_current(sd4, ARR_LEN(sd4), c1, ARR_LEN(c1));
}

START_TEST(test_bu_get_current_proto_1)
{
	do_tests_current();
}
END_TEST

static void build_and_check_deleteme(struct sd *s, int slen,
	struct sd *e, int elen)
{
	char backup[128]="";
	char renamed[128]="";
	struct sdirs *sdirs=setup();
	do_sdirs_init(sdirs);
	build_storage_dirs(sdirs, s, slen);

	// Rename the first one.
	snprintf(backup, sizeof(backup),
		"%s/%s", sdirs->client, s[0].timestamp);
	fail_unless(!rename(backup, sdirs->deleteme));
	assert_bu_list(sdirs, e, elen);

	// Do it again, renamed to something that looks like a timestamp.
	snprintf(renamed, sizeof(renamed), "%s/1010101 1970-01-05 00:00:00",
		sdirs->client);
	fail_unless(!rename(sdirs->deleteme, renamed));
	assert_bu_list(sdirs, e, elen);

	tear_down(&sdirs);
}

static struct sd dm1[] = {
	{ "0000003 1970-01-03 00:00:00", 3, 1, BU_DELETABLE },
	{ "0000005 1970-01-05 00:00:00", 5, 2, BU_CURRENT }
};

static void do_tests_deleteme()
{
	build_and_check_deleteme(sd3, ARR_LEN(sd3), dm1, ARR_LEN(dm1));
}

START_TEST(test_bu_get_deleteme_proto_1)
{
	do_tests_deleteme();
}
END_TEST

Suite *suite_server_bu_get(void)
{
	Suite *s;
	TCase *tc_core;

	s=suite_create("server_bu_get");

	tc_core=tcase_create("Core");
	tcase_set_timeout(tc_core, 60);

	tcase_add_test(tc_core, test_bu_get_proto_1);
	tcase_add_test(tc_core, test_bu_get_with_working_proto_1);
	tcase_add_test(tc_core, test_bu_get_with_running_proto_1);
	tcase_add_test(tc_core, test_bu_get_current_proto_1);
	tcase_add_test(tc_core, test_bu_get_deleteme_proto_1);
	suite_add_tcase(s, tc_core);

	return s;
}
