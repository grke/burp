#include <check.h>
#include <stdint.h>
#include <stdlib.h>
#include <stdio.h>
#include "test.h"
#include "../src/alloc.h"
#include "../src/lock.h"

START_TEST(test_lock)
{
	struct lock *lock;
	fail_unless((lock=lock_alloc())!=NULL);
	lock_free(&lock);
	fail_unless(free_count, alloc_count);
}
END_TEST

Suite *suite_lock(void)
{
	Suite *s;
	TCase *tc_core;

	s=suite_create("lock");

	tc_core=tcase_create("Core");

	tcase_add_test(tc_core, test_lock);
	suite_add_tcase(s, tc_core);

	return s;
}
