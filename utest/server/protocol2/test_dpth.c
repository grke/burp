#include <check.h>
#include <stdint.h>
#include <stdlib.h>
#include <stdio.h>
#include "../../test.h"
#include "../../../src/alloc.h"
#include "../../../src/fsops.h"
#include "../../../src/lock.h"
#include "../../../src/server/protocol2/dpth.h"

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

START_TEST(test_simple)
{
	struct dpth *dpth;
	dpth=setup();
	dpth->need_data_lock=1;
	fail_unless(dpth_mk(dpth)!=NULL);
	fail_unless(dpth->head!=NULL);
	fail_unless(dpth->head->lock!=NULL);
	fail_unless(dpth->head->lock->status==GET_LOCK_GOT);
	dpth->need_data_lock=1;
	fail_unless(dpth_mk(dpth)!=NULL);
printf("%p %s\n", dpth->head, dpth->head->lock->path);
printf("%p %s\n", dpth->tail, dpth->tail->lock->path);
	fail_unless(dpth->tail->lock->status==GET_LOCK_NOT_GOT);
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
