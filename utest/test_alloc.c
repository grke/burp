#include <check.h>
#include <stdlib.h>
#include "../src/alloc.h"

START_TEST(test_alloc)
{
	char *rptr=NULL;
	char *sptr=NULL;
	char *mptr=NULL;
	char *cptr=NULL;
	sptr=(char *)strdup_w("asdfa", __func__);
	rptr=(char *)realloc_w(rptr, 20, __func__);
	rptr=(char *)realloc_w(rptr, 50, __func__);
	mptr=(char *)malloc_w(10, __func__);
	cptr=(char *)calloc_w(2, 40, __func__);
	ck_assert_int_eq(alloc_count, 4);
	ck_assert_int_eq(sptr==NULL, 0);
	ck_assert_int_eq(rptr==NULL, 0);
	ck_assert_int_eq(mptr==NULL, 0);
	ck_assert_int_eq(cptr==NULL, 0);
	free_w(&sptr);
	free_w(&rptr);
	free_w(&mptr);
	free_w(&cptr);
	ck_assert_int_eq(sptr==NULL, 1);
	ck_assert_int_eq(rptr==NULL, 1);
	ck_assert_int_eq(mptr==NULL, 1);
	ck_assert_int_eq(cptr==NULL, 1);
	ck_assert_int_eq(free_count, alloc_count);
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

