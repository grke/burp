#include <check.h>
#include <stdint.h>
#include <stdlib.h>
#include <stdio.h>
#include "../src/base64.h"

struct data
{
        int64_t value;
	const char *where;
	int len;
};

static struct data p[] = {
	{ 0,		"A", 1 },
	{ 1,		"B", 1 },
	{ 2,		"C", 1 },
	{ 10000,	"CcQ", 3 },
	{ -1,		"-B", 2 },
	{ -2,		"-C", 2 },
	{ -10000,	"-CcQ", 4 },
	{ 0x7FFFFFFFFFFFFFFF,	"H//////////", 11 },  // int64 max
	{ -0x7FFFFFFFFFFFFFFF,	"-H//////////", 12 }, // int64 min
	{ 1239054578,	"BJ2njy", 6 },
	{ -1239054578,	"-BJ2njy", 7 },
	{ 999999999999,	"OjUpQ//", 7 },
	{ 16510910,	"++++", 4 },
	// Stuff taken from a genuine manifest file.
	{ 16877,	"EHt", 3 },
	{ 22,		"W", 1 },
	{ 4096,		"BAA", 3 },
	{ 8,		"I", 1 },
	{ 1404621582,	"BTuNMO", 6 },
	{ 1403256802,	"BTo//i", 6 },
	{ 9,		"J", 1 },
};

START_TEST(test_to_base64)
{
	unsigned int i;
	base64_init();
	for(i=0; i<sizeof(p)/sizeof(*p); i++)
	{
		char where[32];
		ck_assert_int_eq(to_base64(p[i].value, where), p[i].len);
		ck_assert_int_eq(strcmp(p[i].where, where), 0);
	}
}
END_TEST

static struct data extra_from[] = {
	// Test some strange input.
	{ 0,		"", 0 },
	{ 0,		" sdff", 0 },
	{ 10000,	"C$cQ", 4 },
	{ 10000,	"C$cQ 82394", 4 },
	{ 10000,	"Cc€Q 82394", 6 },
};

static void do_from_base64(struct data *d, size_t s)
{
	unsigned int i;
	base64_init();
	for(i=0; i<s; i++)
	{
		int64_t value=0;
		ck_assert_int_eq(from_base64(&value, d[i].where), d[i].len);
		ck_assert_int_eq(value, d[i].value);
	}
}

START_TEST(test_from_base64)
{
	do_from_base64(p, sizeof(p)/sizeof(*p));
	do_from_base64(extra_from, sizeof(extra_from)/sizeof(*extra_from));
}
END_TEST

Suite *base64_suite(void)
{
	Suite *s;
	TCase *tc_core;

	s=suite_create("base64");

	tc_core=tcase_create("Core");

	tcase_add_test(tc_core, test_to_base64);
	tcase_add_test(tc_core, test_from_base64);
	suite_add_tcase(s, tc_core);

	return s;
}

int main(void)
{
	int number_failed;
	Suite *s;
	SRunner *sr;

	s=base64_suite();
	sr=srunner_create(s);

	srunner_run_all(sr, CK_NORMAL);
	number_failed = srunner_ntests_failed(sr);
	srunner_free(sr);
	return number_failed == 0 ? EXIT_SUCCESS : EXIT_FAILURE;
}
