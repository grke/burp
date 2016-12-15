#include <check.h>
#include <stdlib.h>
#include "../src/alloc.h"
#include "test.h"

void alloc_check_init(void)
{
	free_count=0;
	alloc_count=0;
	alloc_errors=0;
}

void alloc_check(void)
{
//printf("%d %d\n", free_count, alloc_count);
	fail_unless(free_count==alloc_count);
}

START_TEST(test_alloc)
{
	char *rptr=NULL;
	char *sptr=NULL;
	char *mptr=NULL;
	char *cptr=NULL;
	alloc_counters_reset();
	sptr=(char *)strdup_w("asdfa", __func__);
	rptr=(char *)realloc_w(rptr, 20, __func__);
	rptr=(char *)realloc_w(rptr, 50, __func__);
	mptr=(char *)malloc_w(10, __func__);
	cptr=(char *)calloc_w(2, 40, __func__);
	fail_unless(alloc_count==4);
	fail_unless(sptr!=NULL);
	fail_unless(rptr!=NULL);
	fail_unless(mptr!=NULL);
	fail_unless(cptr!=NULL);
	free_w(&sptr);
	free_w(&rptr);
	free_w(&mptr);
	free_w(&cptr);
	fail_unless(sptr==NULL);
	fail_unless(rptr==NULL);
	fail_unless(mptr==NULL);
	fail_unless(cptr==NULL);
}
END_TEST

Suite *suite_alloc(void)
{
	Suite *s;
	TCase *tc_core;

	s=suite_create("alloc");

	tc_core=tcase_create("Core");

	tcase_add_test(tc_core, test_alloc);
	suite_add_tcase(s, tc_core);

	return s;
}

