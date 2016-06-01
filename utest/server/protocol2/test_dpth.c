#include <check.h>
#include <stdint.h>
#include <stdlib.h>
#include <stdio.h>
#include "../../test.h"
#include "../../../src/alloc.h"
#include "../../../src/fsops.h"
#include "../../../src/hexmap.h"
#include "../../../src/iobuf.h"
#include "../../../src/lock.h"
#include "../../../src/prepend.h"
#include "../../../src/server/protocol2/dpth.h"
#include "../../../src/protocol2/blk.h"
#include "../../builders/build_file.h"

#define LOCKPATH	"utest_dpth"
#define CFILES		LOCKPATH "/cfiles"
#define TESTCLIENT	"testclient"

static void assert_path_components(struct dpth *dpth,
	int prim, int seco, int tert)
{
	fail_unless(dpth->comp[0]==prim);
	fail_unless(dpth->comp[1]==seco);
	fail_unless(dpth->comp[2]==tert);
}

static void assert_components(struct dpth *dpth,
	int prim, int seco, int tert, int sig)
{
	assert_path_components(dpth, prim, seco, tert);
	fail_unless(dpth->comp[3]==sig);
}

static struct dpth *setup(void)
{
	struct dpth *dpth;
	hexmap_init();
	fail_unless(recursive_delete(LOCKPATH)==0);
	fail_unless((dpth=dpth_alloc())!=NULL);
	assert_components(dpth, 0, 0, 0, 0);
	return dpth;
}

static void tear_down(struct dpth **dpth)
{
	dpth_free(dpth);
	fail_unless(recursive_delete(LOCKPATH)==0);
	alloc_check();
}

static int write_to_dpth(struct dpth *dpth, const char *savepathstr)
{
	int ret;
	struct iobuf wbuf;
	struct blk *blk=blk_alloc();
	blk->savepath=savepathstr_with_sig_to_uint64(savepathstr);
	wbuf.buf=strdup_w("abc", __FUNCTION__);
	wbuf.len=3;
	ret=dpth_protocol2_fwrite(dpth, &wbuf, blk);
	free_w(&wbuf.buf);
	blk_free(&blk);
	return ret;
}

static void do_fork(void)
{
	switch(fork())
	{
		case -1: fail_unless(0==1);
			 break;
		case 0: // Child.
		{
			struct dpth *dpth;
			const char *savepath;
			dpth=dpth_alloc();
			dpth_protocol2_init(dpth,
				LOCKPATH,
				TESTCLIENT,
				CFILES,
				MAX_STORAGE_SUBDIRS);
			savepath=dpth_protocol2_mk(dpth);
			write_to_dpth(dpth, savepath);
			sleep(2);
			dpth_free(&dpth);
			exit(0);
		}
		default: break;
	}
	// Parent.
}

static struct dpth *prepare_simple_lock(void)
{
	struct dpth *dpth;
	const char *savepath;
	dpth=setup();
	fail_unless(dpth_protocol2_init(dpth,
		LOCKPATH,
		TESTCLIENT,
		CFILES,
		MAX_STORAGE_SUBDIRS)==0);
	savepath=dpth_protocol2_mk(dpth);
	ck_assert_str_eq(savepath, "0000/0000/0000/0000");
	fail_unless(dpth->head->lock->status==GET_LOCK_GOT);
	// Fill up the data file, so that the next call to dpth_incr_sig will
	// need to open a new one.
	while(dpth->comp[3]<DATA_FILE_SIG_MAX-1)
	{
		fail_unless(write_to_dpth(dpth, savepath)==0);
		fail_unless(dpth_protocol2_incr_sig(dpth)==0);
	}
	return dpth;
}

static void check_simple_lock(struct dpth **dpth,
	const char *expected_savepath, int expected_tert)
{
	const char *savepath;
	fail_unless(dpth_protocol2_incr_sig(*dpth)==0);
	savepath=dpth_protocol2_mk(*dpth);
	ck_assert_str_eq(savepath, expected_savepath);
	assert_components(*dpth, 0, 0, expected_tert, 0);
	fail_unless((*dpth)->head!=(*dpth)->tail);
	fail_unless((*dpth)->head->lock->status==GET_LOCK_GOT);
	fail_unless((*dpth)->tail->lock->status==GET_LOCK_GOT);
	tear_down(dpth);
}

START_TEST(test_simple_lock)
{
	int stat;
	struct dpth *dpth;

	dpth=prepare_simple_lock();

	// Child will lock the next data file. So, the next call to dpth_mk
	// will get the next one after that.
	do_fork();
	sleep(1);

	check_simple_lock(&dpth, "0000/0000/0002/0000", 2);

	wait(&stat);
}
END_TEST

START_TEST(test_simple_lock_with_existant_data_files)
{
	struct dpth *dpth;

	dpth=prepare_simple_lock();

	// Create some data files that did not exist previously. The next call
	// to incr_sig should skip over them.
	build_file(LOCKPATH "/0000/0000/0001", "");
	build_file(LOCKPATH "/0000/0000/0002", "");
	build_file(LOCKPATH "/0000/0000/0003", "");

	check_simple_lock(&dpth, "0000/0000/0004/0000", 4);
}
END_TEST

struct incr_data
{
        uint16_t prim;
        uint16_t seco;
        uint16_t tert;
        uint16_t sig;
        uint16_t prim_expected;
        uint16_t seco_expected;
        uint16_t tert_expected;
        uint16_t sig_expected;
	int ret_expected;
};

static struct incr_data d[] = {
	{ 0x0000, 0x0000, 0x0000, 0x0000,
	  0x0000, 0x0000, 0x0000, 0x0001, 0 },
	{ 0x0000, 0x0000, 0x0000, 0x0001,
	  0x0000, 0x0000, 0x0000, 0x0002, 0 },
	{ 0x0000, 0x0000, 0x0000, 0x1000,
	  0x0000, 0x0000, 0x0001, 0x0000, 0 },
	{ 0x0000, 0x0000, 0x0AAA, 0x0000,
	  0x0000, 0x0000, 0x0AAA, 0x0001, 0 },
	{ 0x0000, 0x0000, 0x0AAA, 0x0AAA,
	  0x0000, 0x0000, 0x0AAA, 0x0AAB, 0 },
	{ 0x0000, 0x0000, 0xFFFF, 0x1000,
	  0x0000, 0x0001, 0x0000, 0x0000, 0 },
	{ 0x0000, 0x3333, 0xFFFF, 0x1000,
	  0x0000, 0x3334, 0x0000, 0x0000, 0 },
	{ 0x0000, 0x7530, 0xFFFF, 0x1000,
	  0x0001, 0x0000, 0x0000, 0x0000, 0 },
	{ 0x3333, 0x3333, 0x3333, 0x0050,
	  0x3333, 0x3333, 0x3333, 0x0051, 0 },
	{ 0x3333, 0xFFFF, 0xFFFF, 0x1000,
	  0x3334, 0x0000, 0x0000, 0x0000, 0 },
	{ 0x7530, 0x7530, 0xFFFF, 0x1000,
	  0x0000, 0x0000, 0x0000, 0x0000, -1 }
};

START_TEST(test_incr_sig)
{
        FOREACH(d)
        {
		struct dpth *dpth;
		dpth=setup();
		fail_unless(dpth_protocol2_init(dpth,
			LOCKPATH,
			TESTCLIENT,
			CFILES,
			MAX_STORAGE_SUBDIRS)==0);
		dpth->comp[0]=d[i].prim;
		dpth->comp[1]=d[i].seco;
		dpth->comp[2]=d[i].tert;
		dpth->comp[3]=d[i].sig;
		fail_unless(dpth_protocol2_incr_sig(dpth)==d[i].ret_expected);
		if(!d[i].ret_expected)
			assert_components(dpth,
				d[i].prim_expected,
				d[i].seco_expected,
				d[i].tert_expected,
				d[i].sig_expected);
		tear_down(&dpth);
        }
}
END_TEST

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
		dpth->comp[3]=0;
		savepath=dpth_protocol2_get_save_path(dpth);
		// Truncate it to remove the sig part.
		savepath[14]='\0';
		path=prepend_s(LOCKPATH, savepath);
		fail_unless(build_path_w(path)==0);
		// Create a file.
		fail_unless((fp=fzp_open(path, "wb"))!=NULL);
		fzp_close(&fp);

		// Now when calling dpth_init(), the components should be
		// incremented appropriately.
		dpth_free(&dpth);
		fail_unless((dpth=dpth_alloc())!=NULL);
		fail_unless(dpth_protocol2_init(dpth,
			LOCKPATH,
			TESTCLIENT,
			CFILES,
			MAX_STORAGE_SUBDIRS)==in[i].ret_expected);
		assert_path_components(dpth,
			in[i].prim_expected,
			in[i].seco_expected,
			in[i].tert_expected);
		
		free_w(&path);
		tear_down(&dpth);
	}
}
END_TEST

Suite *suite_server_protocol2_dpth(void)
{
	Suite *s;
	TCase *tc_core;

	s=suite_create("server_protocol2_dpth");

	tc_core=tcase_create("Core");

	tcase_add_test(tc_core, test_simple_lock);
	tcase_add_test(tc_core, test_simple_lock_with_existant_data_files);
	tcase_add_test(tc_core, test_incr_sig);
	tcase_add_test(tc_core, test_init);
	suite_add_tcase(s, tc_core);

	return s;
}
