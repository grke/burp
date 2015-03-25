#include <check.h>
#include <stdint.h>
#include <stdlib.h>
#include <stdio.h>
#include "test.h"
#include "../src/alloc.h"
#include "../src/lock.h"

static const char *lockfile="utest_lockfile";

START_TEST(test_lock_simple_success)
{
	struct lock *lock;
	fail_unless((lock=lock_alloc())!=NULL);
	fail_unless(!lock_init(lock, lockfile));
	ck_assert_str_eq(lock->path, lockfile);
	fail_unless(lock->status==GET_LOCK_NOT_GOT);
	fail_unless(!lock_test(lockfile));
	lock_get_quick(lock);
	fail_unless(lock->status==GET_LOCK_GOT);
	fail_unless(!lock_release(lock));
	fail_unless(lock->status==GET_LOCK_NOT_GOT);
	lock_free(&lock);
}
END_TEST

START_TEST(test_lock_simple_failure)
{
	int stat;
	struct lock *lock;
	fail_unless((lock=lock_alloc_and_init(lockfile))!=NULL);
	ck_assert_str_eq(lock->path, lockfile);
	fail_unless(lock->status==GET_LOCK_NOT_GOT);
	fail_unless(!lock_test(lockfile));

	// Child will get the lock, and wait.
	// The parent will wait a shorter time, to give the child time to
	// get the lock. The parent will then attempt to get the lock, and
	// it should not succeed.
	switch(fork())
	{
		case -1: fail_unless(0==1);
			break;
		case 0: // Child.
		{
			lock=lock_alloc_and_init(lockfile);
			lock_get_quick(lock);
			sleep(2);
			lock_release(lock);
			lock_free(&lock);
			exit(0);
		}
		default: break;
	}
	// Parent.
	sleep(1);
	fail_unless(lock_test(lockfile)==-1);
	lock_get_quick(lock);
	fail_unless(lock->status==GET_LOCK_NOT_GOT);
	wait(&stat);
	// The child has exited, should now be able to get it.
	fail_unless(!lock_test(lockfile));
	lock_get_quick(lock);
	fail_unless(lock->status==GET_LOCK_GOT);
	fail_unless(!lock_release(lock));
	lock_free(&lock);
}
END_TEST

// FIX THIS: Need to do the above for the case where the lockfile already
// exists on the file system, but nothing is currently locking it.

Suite *suite_lock(void)
{
	Suite *s;
	TCase *tc_core;

	s=suite_create("lock");

	tc_core=tcase_create("Core");

	tcase_add_test(tc_core, test_lock_simple_success);
	tcase_add_test(tc_core, test_lock_simple_failure);
	suite_add_tcase(s, tc_core);

	return s;
}
