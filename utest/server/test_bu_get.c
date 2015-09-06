#include "../test.h"
#include "../../src/alloc.h"
#include "../../src/bu.h"
#include "../../src/conf.h"
#include "../../src/conffile.h"
#include "../../src/fsops.h"
#include "../../src/lock.h"
#include "../../src/prepend.h"
#include "../../src/server/bu_get.h"
#include "../../src/server/protocol1/fdirs.h"
#include "../../src/server/sdirs.h"
#include "../../src/server/timestamp.h"

#define BASE		"utest_bu_get"

static struct sdirs *setup()
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

static void do_sdirs_init(struct sdirs *sdirs, enum protocol protocol)
{
	fail_unless(!sdirs_init(sdirs, protocol,
		BASE, // directory
		"utestclient", // cname
		NULL, // client_lockdir
		"a_group")); // dedup_group
}

static void create_file(const char *path)
{
	FILE *fp;
	fail_unless((fp=fopen(path, "wb"))!=NULL);
	fail_unless(!fclose(fp));
}

struct sd
{
	const char *timestamp;
	unsigned long bno;
	unsigned long index;
	uint16_t flags;
};

static void build_storage_dirs(struct sdirs *sdirs, struct sd *s, int len)
{
	int i=0;
	time_t t=0;
	char backup[128]="";
	char hardlinked[128]="";
	char timestamp_path[128]="";
	for(i=0; i<len; i++)
	{
		snprintf(backup, sizeof(backup),
			"%s/%s", sdirs->client, s[i].timestamp);
		snprintf(timestamp_path, sizeof(timestamp_path),
			"%s/timestamp", backup);
                fail_unless(!build_path_w(backup));
                fail_unless(!mkdir(backup, 0777));
		fail_unless(!timestamp_write(timestamp_path, s[i].timestamp));
		if(s[i].flags & BU_CURRENT)
			fail_unless(!symlink(s[i].timestamp, sdirs->current));
		if(s[i].flags & BU_HARDLINKED)
		{
			snprintf(hardlinked, sizeof(hardlinked),
				"%s/hardlinked", backup);
			create_file(hardlinked);
		}
		t+=60*60*24; // Add one day.
	}
}

static void check_bu_list(struct sdirs *sdirs, struct sd *s, unsigned int len)
{
	unsigned int count=0;
	struct bu *bu;
	struct bu *last;
	struct bu *bu_list=NULL;
	fail_unless(!bu_get_list(sdirs, &bu_list));

	bu=bu_list;
	last=NULL;
	for(count=0; count<len; count++)
	{
		fail_unless(bu!=NULL);
//printf("bu: %lu %s %lu %08X\n", bu->bno, bu->path, bu->index, bu->flags);

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

	bu_list_free(&bu_list);
}

static void build_and_check(struct sd *s, int len, enum protocol protocol)
{
	struct sdirs *sdirs=setup();
	do_sdirs_init(sdirs, protocol);
	build_storage_dirs(sdirs, s, len);
	check_bu_list(sdirs, s, len);
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

static void do_tests(enum protocol protocol)
{
	build_and_check(sd1, ARR_LEN(sd1), protocol);
	build_and_check(sd2, ARR_LEN(sd2), protocol);
	build_and_check(sd3, ARR_LEN(sd3), protocol);
	build_and_check(sd4, ARR_LEN(sd4), protocol);
	build_and_check(sd5, ARR_LEN(sd5), protocol);
}

START_TEST(test_bu_get_proto_1)
{
	do_tests(PROTO_1);
}
END_TEST

START_TEST(test_bu_get_proto_2)
{
	do_tests(PROTO_2);
}
END_TEST

Suite *suite_server_bu_get(void)
{
	Suite *s;
	TCase *tc_core;

	s=suite_create("server_bu_get");

	tc_core=tcase_create("Core");

	tcase_add_test(tc_core, test_bu_get_proto_1);
	tcase_add_test(tc_core, test_bu_get_proto_2);
	suite_add_tcase(s, tc_core);

	return s;
}
