#include "../../../test.h"
#include "../../../../src/alloc.h"
#include "../../../../src/server/protocol2/champ_chooser/hash.h"

static void tear_down(void)
{
	hash_delete_all();
	alloc_check();
}

START_TEST(test_hash_weak_add_alloc_error)
{
	uint64_t f0=0xFF11223344556699;
	alloc_errors=1;
	fail_unless(!hash_weak_add(f0));
	tear_down();
}
END_TEST

START_TEST(test_hash_weak_add)
{
	uint64_t f0=0xFF11223344556699;
	uint64_t f1=0xFF11223344556690;
	uint64_t f2=0xFF00112233445566;
	uint64_t f3=0xFF001122AA445566;
	fail_unless(hash_weak_add(f0)!=NULL);
	fail_unless(hash_weak_add(f1)!=NULL);
	fail_unless(hash_weak_find(f0)!=NULL);
	fail_unless(hash_weak_find(f1)!=NULL);
	fail_unless(hash_weak_find(f2)==NULL);
	fail_unless(hash_weak_find(f3)==NULL);
	tear_down();
}
END_TEST

START_TEST(test_hash_load_fail_to_open)
{
	fail_unless(hash_load("champ", "dir")==HASH_RET_TEMP);
}
END_TEST

Suite *suite_server_protocol2_champ_chooser_hash(void)
{
	Suite *s;
	TCase *tc_core;

	s=suite_create("server_protocol2_champ_chooser_hash");

	tc_core=tcase_create("Core");

	tcase_add_test(tc_core, test_hash_weak_add_alloc_error);
	tcase_add_test(tc_core, test_hash_weak_add);
	tcase_add_test(tc_core, test_hash_load_fail_to_open);
	suite_add_tcase(s, tc_core);

	return s;
}
