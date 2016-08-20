#include "utest/test.h"
#include "alloc.h"
#include "protocol1/handy.h"

static void tear_down(void)
{
	alloc_check();
}

START_TEST(test_enc_setup_no_password)
{
	fail_unless(enc_setup(1 /*encrypt*/, NULL)==NULL);
	tear_down();
}
END_TEST

START_TEST(test_enc_setup_alloc_error)
{
	alloc_errors=1;
	fail_unless(enc_setup(1 /*encrypt*/, "somepass")==NULL);
	tear_down();
}
END_TEST

START_TEST(test_enc_setup_ok)
{
	EVP_CIPHER_CTX *ctx;
	fail_unless((ctx=enc_setup(1 /*encrypt*/, "somepass"))!=NULL);
	free_v((void **)&ctx);
	tear_down();
}
END_TEST

START_TEST(test_send_whole_filel)
{
	uint64_t bytes=0;
	send_whole_filel(
		NULL, // asfd
		CMD_FILE,
		NULL, // datapth
		0, // quick_read
		&bytes,
		NULL, // cntr
		NULL, // bfd
		NULL, // extrameta
		0 // elen
	);
}
END_TEST

Suite *suite_protocol1_handy(void)
{
	Suite *s;
	TCase *tc_core;

	s=suite_create("protocol1_handy");

	tc_core=tcase_create("Core");

	tcase_add_test(tc_core, test_enc_setup_no_password);
	tcase_add_test(tc_core, test_enc_setup_alloc_error);
	tcase_add_test(tc_core, test_enc_setup_ok);
	tcase_add_test(tc_core, test_send_whole_filel);

	suite_add_tcase(s, tc_core);

	return s;
}
