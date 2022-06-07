#include "../test.h"
#include "../../src/server/blocklen.h"

struct end_data
{
	const char *endfile;
	size_t ret_expected;
};

static struct end_data in[] = {
	{ "0", 64 },
	{ "1024", 64 },
	{ "2048", 64 },
	{ "4096", 64 },
	{ "8192", 96 },
	{ "16384", 128 },
	{ "32768", 192 },
	{ "65536", 256 },
	{ "131072", 368 },
	{ "55555555", 7456 },
	{ "555555555", 23584 },
	{ "5555555555", 74544 },
	{ "55555555555", 131072 },
	{ "555555555555", 131072 },
};

START_TEST(test_get_librsync_block_len)
{
	FOREACH(in)
	{
		size_t result=get_librsync_block_len(in[i].endfile);
		fail_unless(result==in[i].ret_expected);
	}
	alloc_check();
}
END_TEST

Suite *suite_server_blocklen(void)
{
	Suite *s;
	TCase *tc_core;

	s=suite_create("server_blocklen");

	tc_core=tcase_create("Core");

	tcase_add_test(tc_core, test_get_librsync_block_len);
	suite_add_tcase(s, tc_core);

	return s;
}
