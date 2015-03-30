#include <check.h>
#include <stdint.h>
#include <stdlib.h>
#include <stdio.h>
#include "test.h"
#include "../src/alloc.h"
#include "../src/lock.h"

static const char *lockfile="utest_lockfile";

static struct lock *setup(void)
{
	static int x=0;
	struct lock *lock;
	// Test both ways of alloc and init.
	if(!(x++ % 2))
		fail_unless((lock=lock_alloc_and_init(lockfile))!=NULL);
	else
	{
		fail_unless((lock=lock_alloc())!=NULL);
		fail_unless(!lock_init(lock, lockfile));
	}
	ck_assert_str_eq(lock->path, lockfile);
	fail_unless(lock->status==GET_LOCK_NOT_GOT);
	return lock;
}

static void assert_can_get_lock(struct lock *lock)
{
	fail_unless(!lock_test(lockfile));
	lock_get_quick(lock);
	fail_unless(lock->status==GET_LOCK_GOT);
	fail_unless(!lock_release(lock));
	fail_unless(lock->status==GET_LOCK_NOT_GOT);
}

static void do_fork(int child_exit_early)
{
	switch(fork())
	{
		case -1: fail_unless(0==1);
			break;
		case 0: // Child.
		{
			struct lock *lock;
			lock=lock_alloc_and_init(lockfile);
			lock_get_quick(lock);
			if(!child_exit_early)
			{
				sleep(2);
				lock_release(lock);
				lock_free(&lock);
			}
			exit(0);
		}
		default: break;
	}
	// Parent.
}

static void run_with_fork(int child_exit_early)
{
	int stat;
	struct lock *lock=setup();

	do_fork(child_exit_early);

	if(!child_exit_early)
	{
		sleep(1);
		fail_unless(lock_test(lockfile)==-1);
		lock_get_quick(lock);
		fail_unless(lock->status==GET_LOCK_NOT_GOT);
		wait(&stat);
	}

	// The child has exited, should now be able to get it.
	assert_can_get_lock(lock);
	lock_free(&lock);
}

START_TEST(test_lock_simple_success)
{
	struct lock *lock;
	lock=setup();
	assert_can_get_lock(lock);
	lock_free(&lock);
}
END_TEST

START_TEST(test_lock_simple_failure)
{
	// Child will get the lock, and wait.
	// The parent will wait a shorter time, to give the child time to
	// get the lock. The parent will then attempt to get the lock, and
	// it should not succeed.
	run_with_fork(0 /* child will not exit early */);
}
END_TEST

START_TEST(test_lock_left_behind)
{
        // Child will get the lock, then exit, leaving an old lockfile behind.
        // The parent will wait and then attempt to get the lock, and it
	// should succeed.
	run_with_fork(1 /* child will exit early */);
}
END_TEST

Suite *suite_lock(void)
{
	Suite *s;
	TCase *tc_core;

	s=suite_create("lock");

	tc_core=tcase_create("Core");

	tcase_add_test(tc_core, test_lock_simple_success);
	tcase_add_test(tc_core, test_lock_simple_failure);
	tcase_add_test(tc_core, test_lock_left_behind);
	suite_add_tcase(s, tc_core);

	return s;
}
