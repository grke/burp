#include <check.h>
#include <stdlib.h>
#include <string.h>
#include "../src/alloc.h"
#include "../src/hexmap.h"
#include "../src/md5.h"
#include "test.h"

START_TEST(test_md5)
{
	uint8_t checksum[MD5_DIGEST_LENGTH];
	struct md5 *md5;

	alloc_counters_reset();
	fail_unless((md5=md5_alloc(__func__))!=NULL);
	fail_unless(md5_init(md5));

	fail_unless(md5_update(md5, "blah", strlen("blah"))!=4);
	fail_unless(md5_final(md5, checksum)!=16);
	ck_assert_str_eq(
		"6f1ed002ab5595859014ebf0951522d9",
		bytes_to_md5str(checksum)
	);

	md5_free(&md5);
	fail_unless(md5==NULL);
	alloc_check();
}
END_TEST

Suite *suite_md5(void)
{
	Suite *s;
	TCase *tc_core;

	s=suite_create("md5");

	tc_core=tcase_create("Core");

	tcase_add_test(tc_core, test_md5);
	suite_add_tcase(s, tc_core);

	return s;
}
