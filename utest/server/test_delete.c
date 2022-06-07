#include "../test.h"
#include "../builders/build.h"
#include "../../src/alloc.h"
#include "../../src/asfd.h"
#include "../../src/bu.h"
#include "../../src/conf.h"
#include "../../src/conffile.h"
#include "../../src/fsops.h"
#include "../../src/iobuf.h"
#include "../../src/lock.h"
#include "../../src/prepend.h"
#include "../../src/server/bu_get.h"
#include "../../src/server/delete.h"
#include "../../src/server/fdirs.h"
#include "../../src/server/sdirs.h"
#include "../../src/server/timestamp.h"
#include "../builders/build_asfd_mock.h"

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

static void do_sdirs_init(struct sdirs *sdirs)
{
	fail_unless(!sdirs_init(sdirs,
		BASE, // directory
		CNAME,
		NULL, // client_lockdir
		"a_group", // dedup_group
		NULL // manual_delete
		));
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

static void build_and_autodelete(
	long keep[], size_t klen, // Keep settings.
	struct sd *s, size_t slen, // Starting backups.
	struct sd *e, size_t elen) // Expected backups.
{
	struct strlist *klist;
	struct sdirs *sdirs=setup();
	do_sdirs_init(sdirs);
	klist=build_keep_strlist(keep, klen);
	build_storage_dirs(sdirs, s, slen);
	fail_unless(!delete_backups(sdirs, CNAME, klist,
		NULL /* manual_delete */));
	assert_bu_list(sdirs, e, elen);
	tear_down(&klist, &sdirs);
}

static long keep4[] = { 4 };

static struct sd ex0[] = {
};

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

static long keep34[] = { 3, 4 };

static struct sd sd5[] = {
	{ "0000001 1970-01-01 00:00:00",  1,  1, BU_DELETABLE },
	{ "0000002 1970-01-02 00:00:00",  2,  2, 0 },
	{ "0000003 1970-01-03 00:00:00",  3,  3, 0 },
	{ "0000004 1970-01-04 00:00:00",  4,  4, 0 },
	{ "0000005 1970-01-05 00:00:00",  5,  5, 0 },
	{ "0000006 1970-01-06 00:00:00",  6,  6, 0 },
	{ "0000007 1970-01-07 00:00:00",  7,  7, 0 },
	{ "0000008 1970-01-08 00:00:00",  8,  8, 0 },
	{ "0000009 1970-01-09 00:00:00",  9,  9, 0 },
	{ "0000010 1970-01-10 00:00:00", 10, 10, 0 },
	{ "0000011 1970-01-11 00:00:00", 11, 11, 0 },
	{ "0000012 1970-01-12 00:00:00", 12, 12, 0 },
	{ "0000013 1970-01-13 00:00:00", 13, 13, 0 },
	{ "0000014 1970-01-14 00:00:00", 14, 14, BU_CURRENT },
};
static struct sd ex5[] = {
	{ "0000003 1970-01-03 00:00:00",  3,  1, BU_DELETABLE },
	{ "0000004 1970-01-04 00:00:00",  4,  2, 0 },
	{ "0000005 1970-01-05 00:00:00",  5,  3, 0 },
	{ "0000006 1970-01-06 00:00:00",  6,  4, 0 },
	{ "0000007 1970-01-07 00:00:00",  7,  5, 0 },
	{ "0000008 1970-01-08 00:00:00",  8,  6, 0 },
	{ "0000009 1970-01-09 00:00:00",  9,  7, 0 },
	{ "0000010 1970-01-10 00:00:00", 10,  8, 0 },
	{ "0000011 1970-01-11 00:00:00", 11,  9, 0 },
	{ "0000012 1970-01-12 00:00:00", 12, 10, 0 },
	{ "0000013 1970-01-13 00:00:00", 13, 11, 0 },
	{ "0000014 1970-01-14 00:00:00", 14, 12, BU_CURRENT },
};

static struct sd sd6[] = {
	{ "0000001 1970-01-01 00:00:00",  1,  1, BU_DELETABLE },
	{ "0000002 1970-01-02 00:00:00",  2,  2, 0 },
	{ "0000003 1970-01-03 00:00:00",  3,  3, BU_HARDLINKED },
	{ "0000004 1970-01-04 00:00:00",  4,  4, BU_DELETABLE },
	{ "0000005 1970-01-05 00:00:00",  5,  5, 0 },
	{ "0000006 1970-01-06 00:00:00",  6,  6, BU_HARDLINKED },
	{ "0000007 1970-01-07 00:00:00",  7,  7, BU_DELETABLE },
	{ "0000008 1970-01-08 00:00:00",  8,  8, 0 },
	{ "0000009 1970-01-09 00:00:00",  9,  9, BU_HARDLINKED },
	{ "0000010 1970-01-10 00:00:00", 10, 10, BU_DELETABLE },
	{ "0000011 1970-01-11 00:00:00", 11, 11, 0 },
	{ "0000012 1970-01-12 00:00:00", 12, 12, BU_HARDLINKED },
	{ "0000013 1970-01-13 00:00:00", 13, 13, BU_DELETABLE },
	{ "0000014 1970-01-14 00:00:00", 14, 14, BU_CURRENT },
};
static struct sd ex6[] = {
	{ "0000003 1970-01-03 00:00:00",  3,  1, BU_HARDLINKED|BU_DELETABLE },
	{ "0000006 1970-01-06 00:00:00",  6,  2, BU_HARDLINKED|BU_DELETABLE },
	{ "0000009 1970-01-09 00:00:00",  9,  3, BU_HARDLINKED|BU_DELETABLE },
	{ "0000012 1970-01-12 00:00:00", 12,  4, BU_HARDLINKED|BU_DELETABLE },
	{ "0000013 1970-01-13 00:00:00", 13,  5, BU_DELETABLE },
	{ "0000014 1970-01-14 00:00:00", 14,  6, BU_CURRENT },
};

static long keep42[] = { 4, 2 };

static struct sd sd7[] = {
	{ "0000003 1970-01-03 00:00:00",  3,  1, BU_HARDLINKED|BU_DELETABLE },
	{ "0000006 1970-01-06 00:00:00",  6,  2, BU_HARDLINKED|BU_DELETABLE },
	{ "0000009 1970-01-09 00:00:00",  9,  3, BU_HARDLINKED|BU_DELETABLE },
	{ "0000012 1970-01-12 00:00:00", 12,  4, BU_HARDLINKED|BU_DELETABLE },
	{ "0000013 1970-01-13 00:00:00", 13,  5, BU_DELETABLE },
	{ "0000014 1970-01-14 00:00:00", 14,  6, BU_CURRENT },
};
static struct sd ex7[] = {
	{ "0000009 1970-01-09 00:00:00",  9,  1, BU_HARDLINKED|BU_DELETABLE },
	{ "0000012 1970-01-12 00:00:00", 12,  2, BU_HARDLINKED|BU_DELETABLE },
	{ "0000013 1970-01-13 00:00:00", 13,  3, BU_DELETABLE },
	{ "0000014 1970-01-14 00:00:00", 14,  4, BU_CURRENT },
};

static long keep422[] = { 4, 2, 2 };
static struct sd sd8[] = {
	{ "0000001 1970-01-01 00:00:00",  1,  1, BU_DELETABLE },
	{ "0000002 1970-01-02 00:00:00",  2,  2, 0 },
	{ "0000003 1970-01-03 00:00:00",  3,  3, BU_HARDLINKED },
	{ "0000004 1970-01-04 00:00:00",  4,  4, BU_DELETABLE },
	{ "0000005 1970-01-05 00:00:00",  5,  5, 0 },
	{ "0000006 1970-01-06 00:00:00",  6,  6, BU_HARDLINKED },
	{ "0000007 1970-01-07 00:00:00",  7,  7, BU_DELETABLE },
	{ "0000008 1970-01-08 00:00:00",  8,  8, 0 },
	{ "0000009 1970-01-09 00:00:00",  9,  9, BU_HARDLINKED },
	{ "0000010 1970-01-10 00:00:00", 10, 10, BU_DELETABLE },
	{ "0000011 1970-01-11 00:00:00", 11, 11, 0 },
	{ "0000012 1970-01-12 00:00:00", 12, 12, BU_HARDLINKED },
	{ "0000013 1970-01-13 00:00:00", 13, 13, BU_DELETABLE },
	{ "0000014 1970-01-14 00:00:00", 14, 14, 0 },
	{ "0000015 1970-01-15 00:00:00", 15, 14, BU_HARDLINKED },
	{ "0000016 1970-01-16 00:00:00", 16, 16, BU_DELETABLE },
	{ "0000017 1970-01-17 00:00:00", 17, 17, 0 },
	{ "0000018 1970-01-18 00:00:00", 18, 18, BU_HARDLINKED|BU_CURRENT },
};
static struct sd ex8[] = {
	{ "0000003 1970-01-03 00:00:00",  3,  1, BU_HARDLINKED|BU_DELETABLE },
	{ "0000011 1970-01-11 00:00:00", 11,  2, BU_DELETABLE },
	{ "0000012 1970-01-12 00:00:00", 12,  3, BU_HARDLINKED },
	{ "0000015 1970-01-15 00:00:00", 15,  4, BU_HARDLINKED|BU_DELETABLE },
	{ "0000016 1970-01-16 00:00:00", 16,  5, BU_DELETABLE },
	{ "0000017 1970-01-17 00:00:00", 17,  6, 0 },
	{ "0000018 1970-01-18 00:00:00", 18,  7, BU_HARDLINKED|BU_CURRENT },
};

static struct sd sd9[] = {
	{ "0000003 1970-01-03 00:00:00",  3,  1, BU_HARDLINKED|BU_DELETABLE },
	{ "0000011 1970-01-11 00:00:00", 11,  2, BU_DELETABLE },
	{ "0000012 1970-01-12 00:00:00", 12,  3, BU_HARDLINKED },
	{ "0000015 1970-01-15 00:00:00", 15,  4, BU_HARDLINKED|BU_DELETABLE },
	{ "0000016 1970-01-16 00:00:00", 16,  5, BU_DELETABLE },
	{ "0000017 1970-01-17 00:00:00", 17,  6, 0 },
	{ "0000018 1970-01-18 00:00:00", 18,  7, BU_HARDLINKED },
	{ "0000019 1970-01-19 00:00:00", 19,  8, BU_CURRENT },
};
static struct sd ex9[] = {
	{ "0000011 1970-01-11 00:00:00", 11,  1, BU_DELETABLE },
	{ "0000012 1970-01-12 00:00:00", 12,  2, BU_HARDLINKED },
	{ "0000016 1970-01-16 00:00:00", 16,  3, BU_DELETABLE },
	{ "0000017 1970-01-17 00:00:00", 17,  4, 0 },
	{ "0000018 1970-01-18 00:00:00", 18,  5, BU_HARDLINKED },
	{ "0000019 1970-01-19 00:00:00", 19,  6, BU_DELETABLE|BU_CURRENT },
};

static struct sd sd10[] = {
	{ "0000011 1970-01-11 00:00:00", 11,  1, BU_DELETABLE },
	{ "0000012 1970-01-12 00:00:00", 12,  2, BU_HARDLINKED },
	{ "0000016 1970-01-16 00:00:00", 16,  3, BU_DELETABLE },
	{ "0000017 1970-01-17 00:00:00", 17,  4, 0 },
	{ "0000018 1970-01-18 00:00:00", 18,  5, BU_HARDLINKED },
	{ "0000019 1970-01-19 00:00:00", 19,  6, BU_DELETABLE },
	{ "0000020 1970-01-20 00:00:00", 20,  7, BU_CURRENT },
};
static struct sd ex10[] = {
	{ "0000012 1970-01-12 00:00:00", 12,  1, BU_HARDLINKED|BU_DELETABLE },
	{ "0000016 1970-01-16 00:00:00", 16,  2, BU_DELETABLE },
	{ "0000017 1970-01-17 00:00:00", 17,  3, 0 },
	{ "0000018 1970-01-18 00:00:00", 18,  4, BU_HARDLINKED },
	{ "0000019 1970-01-19 00:00:00", 19,  5, BU_DELETABLE },
	{ "0000020 1970-01-20 00:00:00", 20,  6, BU_CURRENT },
};

static struct sd sd11[] = {
	{ "0000012 1970-01-12 00:00:00", 12,  1, BU_HARDLINKED|BU_DELETABLE },
	{ "0000016 1970-01-16 00:00:00", 16,  2, BU_DELETABLE },
	{ "0000017 1970-01-17 00:00:00", 17,  3, 0 },
	{ "0000018 1970-01-18 00:00:00", 18,  4, BU_HARDLINKED },
	{ "0000019 1970-01-19 00:00:00", 19,  5, BU_DELETABLE },
	{ "0000020 1970-01-20 00:00:00", 20,  6, 0 },
	{ "0000021 1970-01-21 00:00:00", 21,  7, BU_HARDLINKED|BU_CURRENT },
};
static struct sd ex11[] = {
	{ "0000012 1970-01-12 00:00:00", 12,  1, BU_HARDLINKED|BU_DELETABLE },
	{ "0000017 1970-01-17 00:00:00", 17,  2, BU_DELETABLE },
	{ "0000018 1970-01-18 00:00:00", 18,  3, BU_HARDLINKED },
	{ "0000019 1970-01-19 00:00:00", 19,  4, BU_DELETABLE },
	{ "0000020 1970-01-20 00:00:00", 20,  5, 0 },
	{ "0000021 1970-01-21 00:00:00", 21,  6, BU_HARDLINKED|BU_CURRENT },
};

static struct sd sd12[] = {
	{ "0000012 1970-01-12 00:00:00", 12,  1, BU_HARDLINKED|BU_DELETABLE },
	{ "0000017 1970-01-17 00:00:00", 17,  2, BU_DELETABLE },
	{ "0000018 1970-01-18 00:00:00", 18,  3, BU_HARDLINKED },
	{ "0000019 1970-01-19 00:00:00", 19,  4, BU_DELETABLE },
	{ "0000020 1970-01-20 00:00:00", 20,  5, 0 },
	{ "0000021 1970-01-21 00:00:00", 21,  6, BU_HARDLINKED },
	{ "0000022 1970-01-22 00:00:00", 22,  7, BU_CURRENT },
};
static struct sd ex12[] = {
	{ "0000012 1970-01-12 00:00:00", 12,  1, BU_HARDLINKED|BU_DELETABLE },
	{ "0000018 1970-01-18 00:00:00", 18,  2, BU_HARDLINKED|BU_DELETABLE },
	{ "0000019 1970-01-19 00:00:00", 19,  3, BU_DELETABLE },
	{ "0000020 1970-01-20 00:00:00", 20,  4, 0 },
	{ "0000021 1970-01-21 00:00:00", 21,  5, BU_HARDLINKED },
	{ "0000022 1970-01-22 00:00:00", 22,  6, BU_DELETABLE|BU_CURRENT },
};

static struct sd sd13[] = {
	{ "0000012 1970-01-12 00:00:00", 12,  1, BU_HARDLINKED|BU_DELETABLE },
	{ "0000022 1970-01-22 00:00:00", 22,  2, BU_CURRENT|BU_DELETABLE },
};
static struct sd ex13[] = {
	{ "0000012 1970-01-12 00:00:00", 12,  1, BU_CURRENT|BU_HARDLINKED|BU_DELETABLE },
};

static void do_autodelete_tests_shared()
{
	build_and_autodelete(keep4, ARR_LEN(keep4),
		sd1, ARR_LEN(sd1), sd1, ARR_LEN(sd1));
	build_and_autodelete(keep4, ARR_LEN(keep4),
		sd2, ARR_LEN(sd2), sd2, ARR_LEN(sd2));
	build_and_autodelete(keep4, ARR_LEN(keep4),
		sd3, ARR_LEN(sd3), ex3, ARR_LEN(ex3));
	build_and_autodelete(keep4, ARR_LEN(keep4),
		sd4, ARR_LEN(sd4), ex4, ARR_LEN(ex4));

	build_and_autodelete(keep34, ARR_LEN(keep34),
		sd6, ARR_LEN(sd6), ex6, ARR_LEN(ex6));
	build_and_autodelete(keep42, ARR_LEN(keep42),
		sd7, ARR_LEN(sd7), ex7, ARR_LEN(ex7));

	build_and_autodelete(keep422, ARR_LEN(keep422),
		sd9, ARR_LEN(sd9), ex9, ARR_LEN(ex9));
}

START_TEST(test_autodelete)
{
	do_autodelete_tests_shared();
	build_and_autodelete(keep34, ARR_LEN(keep34),
		sd5, ARR_LEN(sd5), ex5, ARR_LEN(ex5));
	build_and_autodelete(keep422, ARR_LEN(keep422),
		sd8, ARR_LEN(sd8), ex8, ARR_LEN(ex8));
	build_and_autodelete(keep422, ARR_LEN(keep422),
		sd10, ARR_LEN(sd10), ex10, ARR_LEN(ex10));
	build_and_autodelete(keep422, ARR_LEN(keep422),
		sd11, ARR_LEN(sd11), ex11, ARR_LEN(ex11));
	build_and_autodelete(keep422, ARR_LEN(keep422),
		sd12, ARR_LEN(sd12), ex12, ARR_LEN(ex12));
}
END_TEST

static struct ioevent_list areads;
static struct ioevent_list awrites;

static void setup_asfd_ok(struct asfd *asfd)
{
	int w=0;
	asfd_assert_write(asfd, &w, 0, CMD_GEN, "ok");
}

static void setup_asfd_not_found(struct asfd *asfd)
{
	int w=0;
	asfd_assert_write(asfd, &w, 0, CMD_ERROR, "backup not found");
}

static void setup_asfd_not_deletable(struct asfd *asfd)
{
	int w=0;
	asfd_assert_write(asfd, &w, 0, CMD_ERROR, "backup not deletable");
}

static void build_and_userdelete(
	int expected_ret,
	const char *backup_str,
	struct sd *s, size_t slen, // Starting backups.
	struct sd *e, size_t elen, // Expected backups.
	void setup_asfd_callback(struct asfd *asfd))
{
	struct sdirs *sdirs;
	struct asfd *asfd;
	sdirs=setup();
	asfd=asfd_mock_setup(&areads, &awrites);
	setup_asfd_callback(asfd);
	do_sdirs_init(sdirs);
	build_storage_dirs(sdirs, s, slen);
	fail_unless(do_delete_server(asfd,
		sdirs,
		NULL, // cntr
		CNAME,
		backup_str,
		NULL // manual_delete
	)==expected_ret);
	assert_bu_list(sdirs, e, elen);
        asfd_free(&asfd);
        asfd_mock_teardown(&areads, &awrites);
	tear_down(NULL, &sdirs);
}

static void do_userdelete_tests_shared()
{
	build_and_userdelete( 0, "1",
		sd1, ARR_LEN(sd1), ex0, ARR_LEN(ex0), setup_asfd_ok);
	build_and_userdelete( 0, "22",
		sd13, ARR_LEN(sd13), ex13, ARR_LEN(ex13), setup_asfd_ok);
	build_and_userdelete(-1, "2",
		sd1, ARR_LEN(sd1), sd1, ARR_LEN(sd1), setup_asfd_not_found);

	build_and_userdelete(-1, "junk",
		sd3, ARR_LEN(sd3), sd3, ARR_LEN(sd3), setup_asfd_not_found);
}

START_TEST(test_userdelete)
{
	do_userdelete_tests_shared();
	build_and_userdelete(-1, "2",
		sd3, ARR_LEN(sd3), sd3, ARR_LEN(sd3), setup_asfd_not_deletable);
	build_and_userdelete(-1, "5",
		sd3, ARR_LEN(sd3), sd3, ARR_LEN(sd3), setup_asfd_not_deletable);
}
END_TEST

Suite *suite_server_delete(void)
{
	Suite *s;
	TCase *tc_core;

	s=suite_create("server_delete");

	tc_core=tcase_create("Core");
        tcase_set_timeout(tc_core, 20);
	tcase_add_test(tc_core, test_autodelete);
	tcase_add_test(tc_core, test_userdelete);
	suite_add_tcase(s, tc_core);

	return s;
}
