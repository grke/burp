#include <check.h>
#include <stdint.h>
#include <stdlib.h>
#include <stdio.h>
#include "test.h"
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
	base64_init();
	FOREACH(p)
	{
		char where[32];
		fail_unless(to_base64(p[i].value, where)==p[i].len);
		fail_unless(!strcmp(p[i].where, where));
	}
}
END_TEST

static struct data extra_from[] = {
	// Test some strange input.
	{ 0,		"", 0 },
	{ 10000,	" C$cQ", 5 },
	{ 10000,	"C$cQ", 4 },
	{ 10000,	"C$cQ 82394", 4 },
	{ 10000,	"Cc€Q 82394", 6 },
	{ 9184233123957407608,	"812908312903012923901239081232394", 33 }
};

static void do_from_base64(struct data *d, size_t s)
{
	unsigned int i;
	base64_init();
	for(i=0; i<s; i++)
	{
		int64_t value=0;
		fail_unless(from_base64(&value, d[i].where)==d[i].len);
		fail_unless(value==d[i].value);
	}
}

START_TEST(test_from_base64)
{
	do_from_base64(p, ARR_LEN(p));
	do_from_base64(extra_from, ARR_LEN(extra_from));
}
END_TEST

Suite *suite_base64(void)
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
