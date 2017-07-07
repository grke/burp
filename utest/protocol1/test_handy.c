#include "../test.h"
#include "../../src/alloc.h"
#include "../../src/protocol1/handy.h"

static void tear_down(void)
{
	alloc_check();
}

START_TEST(test_enc_setup_no_password)
{
	fail_unless(enc_setup(1 /*encrypt*/, NULL, 1)==NULL);
	tear_down();
}
END_TEST

START_TEST(test_enc_setup_ok)
{
	EVP_CIPHER_CTX *ctx;
	fail_unless((ctx=enc_setup(1 /*encrypt*/, "somepass", 1))!=NULL);
	EVP_CIPHER_CTX_cleanup(ctx);
	EVP_CIPHER_CTX_free(ctx);
	tear_down();
}
END_TEST

START_TEST(test_send_whole_filel)
{
	uint64_t bytes=0;
	enum send_e result;
	result=send_whole_filel(
		NULL, // asfd
#ifdef HAVE_WIN32
		CMD_FILE,
#endif
		NULL, // datapth
		0, // quick_read
		&bytes,
		NULL, // cntr
		NULL, // bfd
		NULL, // extrameta
		0 // elen
	);
	fail_unless(result==SEND_FATAL);
}
END_TEST

Suite *suite_protocol1_handy(void)
{
	Suite *s;
	TCase *tc_core;

	s=suite_create("protocol1_handy");

	tc_core=tcase_create("Core");

	tcase_add_test(tc_core, test_enc_setup_no_password);
	tcase_add_test(tc_core, test_enc_setup_ok);
	tcase_add_test(tc_core, test_send_whole_filel);

	suite_add_tcase(s, tc_core);

	return s;
}
