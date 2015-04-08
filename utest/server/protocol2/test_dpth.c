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
			int x;
			struct dpth *dpth;
			dpth=dpth_alloc(lockpath);
			dpth->need_data_lock=1;
			dpth_init(dpth);
			dpth_mk(dpth);
			x=write_to_dpth(dpth, "0000/0000/0001");
printf("CHILD %d %d\n", x, dpth->tert);
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
	struct dpth *dpth;
	dpth=setup();
	dpth->need_data_lock=1;
	fail_unless(dpth_init(dpth)==0);
	fail_unless(dpth_mk(dpth)!=NULL);
	fail_unless(dpth->head!=NULL);
	fail_unless(dpth->head->lock!=NULL);
	fail_unless(dpth->head->lock->status==GET_LOCK_GOT);
	fail_unless(write_to_dpth(dpth, "0000/0000/0000")==0);

	do_fork();
	sleep(1);
/*
	dpth_init(dpth);
	dpth_mk(dpth);
	fail_unless(dpth->head->lock->status==GET_LOCK_GOT);
printf("p: %p\n", dpth->head);
printf("p: %p\n", dpth->tail);
	assert_components(dpth, 0, 0, 2, 0);
	dpth_free(&dpth);
*/
fail_unless(1==0);
/*
	dpth->need_data_lock=1;
	dpth->tert++;
	fail_unless(dpth_mk(dpth)!=NULL);
	fail_unless(dpth->tail->lock->status==GET_LOCK_GOT);
	assert_components(dpth, 0, 0, 2, 0);
*/
	tear_down(&dpth);
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
