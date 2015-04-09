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
#include "../../../src/server/protocol2/dpth.h"
#include "../../../src/protocol2/blk.h"

static const char *lockpath="utest_dpth";

static void assert_components(struct dpth *dpth,
	int prim, int seco, int tert, int sig)
{
	fail_unless(dpth->prim==prim);
	fail_unless(dpth->seco==seco);
	fail_unless(dpth->tert==tert);
	fail_unless(dpth->sig==sig);
}

static struct dpth *setup(void)
{
	struct dpth *dpth;
	hexmap_init();
	fail_unless(recursive_delete(lockpath, "", 1)==0);
	fail_unless((dpth=dpth_alloc(lockpath))!=NULL);
	assert_components(dpth, 0, 0, 0, 0);
	return dpth;
}

static void tear_down(struct dpth **dpth)
{
	dpth_free(dpth);
	fail_unless(recursive_delete(lockpath, "", 1)==0);
	fail_unless(free_count==alloc_count);
}

static int write_to_dpth(struct dpth *dpth, const char *savepathstr)
{
	int ret;
	struct iobuf wbuf;
	struct blk *blk=blk_alloc();
	savepathstr_to_bytes(savepathstr, blk->savepath);
	wbuf.buf=strdup_w("abc", __FUNCTION__);
	wbuf.len=3;
	ret=dpth_fwrite(dpth, &wbuf, blk);
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
			dpth=dpth_alloc(lockpath);
			dpth_init(dpth);
			savepath=dpth_mk(dpth);
			write_to_dpth(dpth, savepath);
			sleep(2);
			dpth_free(&dpth);
			exit(0);
		}
		default: break;
	}
	// Parent.
}

START_TEST(test_simple)
{
	int stat;
	struct dpth *dpth;
	const char *savepath;
	dpth=setup();
	fail_unless(dpth_init(dpth)==0);
	savepath=dpth_mk(dpth);
	ck_assert_str_eq(savepath, "0000/0000/0000/0000");
	fail_unless(dpth->head->lock->status==GET_LOCK_GOT);
	// Fill up the data file, so that the next call to dpth_incr_sig will
	// need to open a new one.
	while(dpth->sig<DATA_FILE_SIG_MAX-1)
	{
		fail_unless(write_to_dpth(dpth, savepath)==0);
		fail_unless(dpth_incr_sig(dpth)==0);
	}

	// Child will lock the next data file. So, the next call to dpth_mk
	// will get the next one after that.
	do_fork();
	sleep(1);

	fail_unless(dpth_incr_sig(dpth)==0);
	savepath=dpth_mk(dpth);
	ck_assert_str_eq(savepath, "0000/0000/0002/0000");
	assert_components(dpth, 0, 0, 2, 0);
	fail_unless(dpth->head!=dpth->tail);
	fail_unless(dpth->head->lock->status==GET_LOCK_GOT);
	fail_unless(dpth->tail->lock->status==GET_LOCK_GOT);
	tear_down(&dpth);
	wait(&stat);
}
END_TEST

Suite *suite_server_protocol2_dpth(void)
{
	Suite *s;
	TCase *tc_core;

	s=suite_create("server_protocol2_dpth");

	tc_core=tcase_create("Core");

	tcase_add_test(tc_core, test_simple);
	suite_add_tcase(s, tc_core);

	return s;
}
