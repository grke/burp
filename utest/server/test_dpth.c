#include <check.h>
#include <stdint.h>
#include <stdlib.h>
#include <stdio.h>
#include "../test.h"
#include "../../src/alloc.h"
#include "../../src/conf.h"
#include "../../src/conffile.h"
#include "../../src/fsops.h"
#include "../../src/hexmap.h"
#include "../../src/iobuf.h"
#include "../../src/lock.h"
#include "../../src/prepend.h"
#include "../../src/server/dpth.h"

static const char *basepath="utest_dpth";

static void assert_components(struct dpth *dpth,
	int prim, int seco, int tert)
{
	fail_unless(dpth->comp[0]==prim);
	fail_unless(dpth->comp[1]==seco);
	fail_unless(dpth->comp[2]==tert);
}

static struct dpth *setup(void)
{
	struct dpth *dpth;
	fail_unless(recursive_delete(basepath)==0);
	fail_unless((dpth=dpth_alloc())!=NULL);
	assert_components(dpth, 0, 0, 0);

	return dpth;
}

static void tear_down(struct dpth **dpth)
{
	dpth_free(dpth);
	fail_unless(recursive_delete(basepath)==0);
	alloc_check();
}

struct init_data
{
        uint16_t prim;
        uint16_t seco;
        uint16_t tert;
        uint16_t prim_expected;
        uint16_t seco_expected;
        uint16_t tert_expected;
	int ret_expected;
};

static struct init_data in[] = {
	{ 0x0000, 0x0000, 0x0000,
	  0x0000, 0x0000, 0x0001, 0 },
	{ 0x0000, 0x0000, 0xAAAA,
	  0x0000, 0x0000, 0xAAAB, 0 },
	{ 0x0000, 0x0000, 0xFFFF,
	  0x0000, 0x0001, 0x0000, 0 },
	{ 0x0000, 0x3333, 0xFFFF,
	  0x0000, 0x3334, 0x0000, 0 },
	{ 0x0000, 0x7530, 0xFFFF,
	  0x0001, 0x0000, 0x0000, 0 },
	{ 0x3333, 0xFFFF, 0xFFFF,
	  0x3334, 0x0000, 0x0000, 0 },
	{ 0x7530, 0x7530, 0xFFFF,
	  0x0000, 0x0000, 0x0000, -1 }
};

START_TEST(test_incr)
{
	FOREACH(in)
	{
		struct dpth *dpth;
		dpth=setup();
		fail_unless(dpth_init(dpth,
			basepath, MAX_STORAGE_SUBDIRS)==0);
		dpth->comp[0]=in[i].prim;
		dpth->comp[1]=in[i].seco;
		dpth->comp[2]=in[i].tert;
		fail_unless(dpth_incr(dpth)==in[i].ret_expected);
		if(!in[i].ret_expected)
			assert_components(dpth,
				in[i].prim_expected,
				in[i].seco_expected,
				in[i].tert_expected);
		tear_down(&dpth);
	}
}
END_TEST

START_TEST(test_init)
{
	FOREACH(in)
	{
		struct fzp *fp=NULL;
		char *path=NULL;
		struct dpth *dpth;
		char *savepath;
		dpth=setup();
		dpth->comp[0]=in[i].prim;
		dpth->comp[1]=in[i].seco;
		dpth->comp[2]=in[i].tert;
		savepath=dpth_mk(dpth, 0, CMD_ERROR);
		path=prepend_s(basepath, savepath);
		fail_unless(build_path_w(path)==0);
		// Create a file.
		fail_unless((fp=fzp_open(path, "wb"))!=NULL);
		fzp_close(&fp);

		// Now when calling dpth_init(), the components should be
		// incremented appropriately.
		dpth_free(&dpth);
		fail_unless((dpth=dpth_alloc())!=NULL);
		fail_unless(dpth_init(dpth,
			basepath, MAX_STORAGE_SUBDIRS)
			==in[i].ret_expected);
		assert_components(dpth,
				in[i].prim_expected,
				in[i].seco_expected,
				in[i].tert_expected);

		free_w(&path);
		tear_down(&dpth);
	}
}
END_TEST

static void assert_mk(struct dpth *dpth, int compression, enum cmd cmd,
	const char *expected)
{
	ck_assert_str_eq(dpth_mk(dpth, compression, cmd), expected);
}

START_TEST(test_mk)
{
	struct dpth *dpth=setup();
	dpth->comp[0]=9;
	dpth->comp[1]=9;
	dpth->comp[2]=9;
	assert_mk(dpth, 0, CMD_FILE, "0009/0009/0009");
	assert_mk(dpth, 5, CMD_FILE, "0009/0009/0009.gz");
	assert_mk(dpth, 0, CMD_EFS_FILE, "0009/0009/0009");
	assert_mk(dpth, 5, CMD_EFS_FILE, "0009/0009/0009");
	tear_down(&dpth);
}
END_TEST

struct str_data
{
        uint16_t prim;
        uint16_t seco;
        uint16_t tert;
	char str[15];
        uint16_t prim_expected;
        uint16_t seco_expected;
        uint16_t tert_expected;
	int ret_expected;
};

static struct str_data str[] = {
	{ 0x0000,0x0000,0x0000, "t/some/path",    0x0000,0x0000,0x0000,  0 },
	{ 0x0000,0x0000,0x0000, "invalid",        0x0000,0x0000,0x0000, -1 },
	{ 0x0000,0x0000,0x0000, "0000/0G00/0000", 0x0000,0x0000,0x0000, -1 },
	{ 0x0000,0x0000,0x0000, "0000/0000/0010", 0x0000,0x0000,0x0010,  0 },
	{ 0x0000,0x0000,0x0000, "0000/0011/0010", 0x0000,0x0011,0x0010,  0 },
	{ 0x0000,0x0000,0x0000, "0012/0011/0010", 0x0012,0x0011,0x0010,  0 },
	{ 0x0000,0x0000,0xAAAA, "0000/0000/0010", 0x0000,0x0000,0xAAAA,  0 },
	{ 0x0000,0xAAAA,0x0000, "0000/0010/0000", 0x0000,0xAAAA,0x0000,  0 },
	{ 0x1111,0x0000,0x0000, "1110/1111/1111", 0x1111,0x0000,0x0000,  0 },
	{ 0x1111,0x2222,0x0000, "1110/3333/4444", 0x1111,0x2222,0x0000,  0 },
	{ 0x1111,0x2222,0x3333, "1110/3333/4444", 0x1111,0x2222,0x3333,  0 },
	{ 0x1111,0x2222,0x3333, "1112/1111/1111", 0x1112,0x1111,0x1111,  0 }
};

START_TEST(test_set_from_string)
{
	FOREACH(str)
	{
		int ret;
		struct dpth *dpth;
		dpth=setup();
		dpth->comp[0]=str[i].prim;
		dpth->comp[1]=str[i].seco;
		dpth->comp[2]=str[i].tert;
		ret=dpth_set_from_string(dpth, str[i].str);
		fail_unless(ret==str[i].ret_expected);
		assert_components(dpth,
				str[i].prim_expected,
				str[i].seco_expected,
				str[i].tert_expected);
		tear_down(&dpth);
	}
}
END_TEST

Suite *suite_server_dpth(void)
{
	Suite *s;
	TCase *tc_core;

	s=suite_create("server_dpth");

	tc_core=tcase_create("Core");

	tcase_add_test(tc_core, test_incr);
	tcase_add_test(tc_core, test_init);
	tcase_add_test(tc_core, test_mk);
	tcase_add_test(tc_core, test_set_from_string);
	suite_add_tcase(s, tc_core);

	return s;
}
