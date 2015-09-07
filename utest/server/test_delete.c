#include "../test.h"
#include "../builders/build.h"
#include "../../src/alloc.h"
#include "../../src/bu.h"
#include "../../src/conf.h"
#include "../../src/conffile.h"
#include "../../src/fsops.h"
#include "../../src/lock.h"
#include "../../src/prepend.h"
#include "../../src/server/bu_get.h"
#include "../../src/server/delete.h"
#include "../../src/server/protocol1/fdirs.h"
#include "../../src/server/sdirs.h"
#include "../../src/server/timestamp.h"

#define BASE		"utest_delete"
#define CNAME		"utestclient"


static struct sdirs *setup(void)
{
	struct sdirs *sdirs;
	fail_unless(recursive_delete(BASE)==0);
	fail_unless((sdirs=sdirs_alloc())!=NULL);
	return sdirs;
}

static void tear_down(struct strlist **klist, struct sdirs **sdirs)
{
	sdirs_free(sdirs);
	strlists_free(klist);
	fail_unless(recursive_delete(BASE)==0);
	alloc_check();
}

static void do_sdirs_init(struct sdirs *sdirs, enum protocol protocol)
{
	fail_unless(!sdirs_init(sdirs, protocol,
		BASE, // directory
		CNAME,
		NULL, // client_lockdir
		"a_group")); // dedup_group
}

static struct strlist *build_keep_strlist(long keep[], size_t len)
{
	size_t l;
	char tmp[8]="";
	struct strlist *list=NULL;
	for(l=0; l<len; l++)
	{
		snprintf(tmp, sizeof(tmp), "%lu", keep[l]);
		fail_unless(!strlist_add(&list, tmp, (long)keep[l]));
	}
	return list;
}

static void build_and_delete(enum protocol protocol,
	long keep[], size_t klen, // Keep settings.
	struct sd *s, size_t slen, // Starting backups.
	struct sd *e, size_t elen) // Expected backups.
{
	struct strlist *klist;
	struct sdirs *sdirs=setup();
	do_sdirs_init(sdirs, protocol);
	klist=build_keep_strlist(keep, klen);
	build_storage_dirs(sdirs, s, slen);
	fail_unless(!delete_backups(sdirs, CNAME, klist));
	assert_bu_list(sdirs, e, elen);
	tear_down(&klist, &sdirs);
}

static long keep4[] = { 4 };

static struct sd sd1[] = {
	{ "0000001 1970-01-05 00:00:00", 1, 1, BU_CURRENT|BU_DELETABLE }
};

static struct sd sd2[] = {
        { "0000001 1970-01-01 00:00:00", 1, 1, BU_DELETABLE },
        { "0000002 1970-01-02 00:00:00", 2, 2, 0 },
        { "0000003 1970-01-03 00:00:00", 3, 3, 0 },
        { "0000004 1970-01-04 00:00:00", 4, 4, BU_CURRENT },
};

static struct sd sd3[] = {
        { "0000001 1970-01-01 00:00:00", 1, 1, BU_DELETABLE },
        { "0000002 1970-01-02 00:00:00", 2, 2, 0 },
        { "0000003 1970-01-03 00:00:00", 3, 3, 0 },
        { "0000004 1970-01-04 00:00:00", 4, 4, 0 },
        { "0000005 1970-01-05 00:00:00", 5, 5, BU_CURRENT },
};
static struct sd ex3[] = {
        { "0000002 1970-01-02 00:00:00", 2, 1, BU_DELETABLE },
        { "0000003 1970-01-03 00:00:00", 3, 2, 0 },
        { "0000004 1970-01-04 00:00:00", 4, 3, 0 },
        { "0000005 1970-01-05 00:00:00", 5, 4, BU_CURRENT },
};

static struct sd sd4[] = {
        { "0000001 1970-01-01 00:00:00", 1, 1, BU_DELETABLE },
        { "0000002 1970-01-02 00:00:00", 2, 2, 0 },
        { "0000003 1970-01-03 00:00:00", 3, 3, 0 },
        { "0000004 1970-01-04 00:00:00", 4, 4, 0 },
        { "0000005 1970-01-05 00:00:00", 5, 5, 0 },
        { "0000006 1970-01-06 00:00:00", 6, 6, 0 },
        { "0000007 1970-01-07 00:00:00", 7, 7, BU_CURRENT },
};
static struct sd ex4[] = {
        { "0000004 1970-01-04 00:00:00", 4, 1, BU_DELETABLE },
        { "0000005 1970-01-05 00:00:00", 5, 2, 0 },
        { "0000006 1970-01-06 00:00:00", 6, 3, 0 },
        { "0000007 1970-01-07 00:00:00", 7, 4, BU_CURRENT },
};

static void do_tests(enum protocol protocol)
{
	build_and_delete(protocol,
		keep4, ARR_LEN(keep4), sd1, ARR_LEN(sd1), sd1, ARR_LEN(sd1));
	build_and_delete(protocol,
		keep4, ARR_LEN(keep4), sd2, ARR_LEN(sd2), sd2, ARR_LEN(sd2));
	build_and_delete(protocol,
		keep4, ARR_LEN(keep4), sd3, ARR_LEN(sd3), ex3, ARR_LEN(ex3));
	build_and_delete(protocol,
		keep4, ARR_LEN(keep4), sd4, ARR_LEN(sd4), ex4, ARR_LEN(ex4));
}

START_TEST(test_delete_proto_1)
{
	do_tests(PROTO_1);
}
END_TEST

START_TEST(test_delete_proto_2)
{
	do_tests(PROTO_2);
}
END_TEST

Suite *suite_server_delete(void)
{
	Suite *s;
	TCase *tc_core;

	s=suite_create("server_delete");

	tc_core=tcase_create("Core");

	tcase_add_test(tc_core, test_delete_proto_1);
	tcase_add_test(tc_core, test_delete_proto_2);
	suite_add_tcase(s, tc_core);

	return s;
}
