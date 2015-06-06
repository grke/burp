#include <check.h>
#include <stdint.h>
#include <stdlib.h>
#include <stdio.h>
#include "../../test.h"
#include "../../../src/alloc.h"
#include "../../../src/conf.h"
#include "../../../src/conffile.h"
#include "../../../src/fsops.h"
#include "../../../src/hexmap.h"
#include "../../../src/iobuf.h"
#include "../../../src/lock.h"
#include "../../../src/prepend.h"
#include "../../../src/server/protocol1/dpth.h"

static const char *basepath="utest_dpth";

static void assert_components(struct dpth *dpth,
	int prim, int seco, int tert)
{
	fail_unless(dpth->prim==prim);
	fail_unless(dpth->seco==seco);
	fail_unless(dpth->tert==tert);
}

static struct dpth *setup(void)
{
	struct dpth *dpth;
	hexmap_init();
	fail_unless(recursive_delete(basepath, "", 1)==0);
	fail_unless((dpth=dpth_alloc())!=NULL);
	assert_components(dpth, 0, 0, 0);

	return dpth;
}

static void tear_down(struct dpth **dpth)
{
	dpth_free(dpth);
	fail_unless(recursive_delete(basepath, "", 1)==0);
	fail_unless(free_count==alloc_count);
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
		fail_unless(dpth_protocol1_init(dpth,
			basepath, MAX_STORAGE_SUBDIRS)==0);
		dpth->prim=in[i].prim;
		dpth->seco=in[i].seco;
		dpth->tert=in[i].tert;
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
		dpth->prim=in[i].prim;
		dpth->seco=in[i].seco;
		dpth->tert=in[i].tert;
		savepath=dpth_protocol1_mk(dpth, 0, CMD_ERROR);
		path=prepend_s(basepath, savepath);
		fail_unless(build_path_w(path)==0);
		// Create a file.
		fail_unless((fp=fzp_open(path, "wb"))!=NULL);
		fzp_close(&fp);

		// Now when calling dpth_init(), the components should be
		// incremented appropriately.
		dpth_free(&dpth);
		fail_unless((dpth=dpth_alloc())!=NULL);
		fail_unless(dpth_protocol1_init(dpth,
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
	ck_assert_str_eq(dpth_protocol1_mk(dpth, compression, cmd), expected);
}

START_TEST(test_mk)
{
	struct dpth *dpth=setup();
	dpth->prim=9;
	dpth->seco=9;
	dpth->tert=9;
	assert_mk(dpth, 0, CMD_FILE, "0009/0009/0009");
	assert_mk(dpth, 5, CMD_FILE, "0009/0009/0009.gz");
	assert_mk(dpth, 0, CMD_EFS_FILE, "0009/0009/0009");
	assert_mk(dpth, 5, CMD_EFS_FILE, "0009/0009/0009");
	tear_down(&dpth);
}
END_TEST

Suite *suite_server_protocol1_dpth(void)
{
	Suite *s;
	TCase *tc_core;

	s=suite_create("server_protocol1_dpth");

	tc_core=tcase_create("Core");

	tcase_add_test(tc_core, test_incr);
	tcase_add_test(tc_core, test_init);
	tcase_add_test(tc_core, test_mk);
	suite_add_tcase(s, tc_core);

	return s;
}
