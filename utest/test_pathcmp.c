#include <check.h>
#include <stdlib.h>
#include "test.h"
#include "../src/pathcmp.h"

#define SAME	0
#define APRIOR	-1
#define ALATER	1

struct data
{
	int expected;
	const char *a;
	const char *b;
};

static struct data p[] = {
	{ SAME,		NULL,		NULL },
	{ APRIOR,	NULL,		"" },
	{ ALATER,	"",		NULL },
	{ SAME,		"",		"" },
	{ SAME,		"/",		"/" },
	{ SAME,		"C:",		"C:" },
	{ APRIOR,	"a",		"b" },
	{ ALATER,	"b",		"a" },
	{ APRIOR,	"A",		"a" },
	{ ALATER,	"a",		"B" },
	{ SAME,		"/some/path",	"/some/path" },
	{ ALATER,	"/some/path/",	"/some/path" },
	{ APRIOR,	"/some/path",	"/some/path/" },
	{ APRIOR,	"/some/path",	"/some/pathy" },
	{ ALATER,	"/some/path",	"/som/path" },
	{ ALATER,	"/long/p/a/t/h","/long/p/a/s/t" }
};

START_TEST(test_pathcmp)
{
	FOREACH(p) fail_unless(pathcmp(p[i].a, p[i].b)==p[i].expected);
}
END_TEST

static struct data s[] = {
	{ 0,		NULL,		NULL },
	{ 0,		"",		NULL },
	{ 0,		NULL,		"" },
	{ 1,		"",		"" },
	{ 2,		"/",		"/" },
	{ 1,		"",		"/" },
	{ 3,		"/some/path",	"/some/path" },
	{ 0,		"/some/path",	"/some/pathx" },
	{ 0,		"/some/pathx",	"/some/path" },
	{ 2,		"/",		"/a/b/c" },
	{ 3,		"/a/b",		"/a/b/c/d" },
	{ 0,		"/d/c/b/a",	"/a/b/c/d" },
	{ 2,		"/bin",		"/bin/bash" },
	{ 3,		"/bin/",	"/bin/bash" },
	{ 1,		"C:",		"C:" },
	{ 1,		"C:",		"C:/" },
	{ 0,		"C:/",		"C:" },
	{ 2,		"C:/",		"C:/Program Files" },
};

START_TEST(test_is_subdir)
{
	FOREACH(s) fail_unless(is_subdir(s[i].a, s[i].b)==s[i].expected);
}
END_TEST

Suite *suite_pathcmp(void)
{
	Suite *s;
	TCase *tc_core;

	s=suite_create("pathcmp");

	tc_core=tcase_create("Core");

	tcase_add_test(tc_core, test_pathcmp);
	tcase_add_test(tc_core, test_is_subdir);
	suite_add_tcase(s, tc_core);

	return s;
}
