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
	{ ALATER,	"/long/p/a/t/h","/long/p/a/s/t" },
	{ APRIOR,	"/some/path",	"/someppath" },
	{ APRIOR,	"/some/path",	"/some path" },
};

START_TEST(test_pathcmp)
{
	FOREACH(p) fail_unless(pathcmp(p[i].a, p[i].b)==p[i].expected);
}
END_TEST

struct data_s
{
	int expected;
	int a;
	int b;
};

// pathcmp has a bug that we have to live with, where it compares signed chars
// instead of unsigned chars. It means that it orders chars above 127 (0x7F)
// first.
static struct data_s p_s[] = {
	{ APRIOR,	0x00,		0xFF },
	{ APRIOR,	0x7E,		0x7F },
	{ APRIOR,	0x80,		0x7F },
	{ APRIOR,	0x80,		0x81 },
};

START_TEST(test_pathcmp_s)
{
	char a[2]="";
	char b[2]="";
	FOREACH(p_s)
	{
		snprintf(a, sizeof(a), "%c", p_s[i].a);
		snprintf(b, sizeof(b), "%c", p_s[i].b);
		fail_unless(pathcmp(a, b)==p_s[i].expected);
	}
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

struct abs
{
	int expected_dot;
	int expected_abs;
	const char *a;
};

static struct abs a[] = {
	{ 0, 0, "foo/bar" },
#ifndef HAVE_WIN32
	{ 0, 1, "/foo/bar" },
	{ 0, 1, "/foo..bar" },
	{ 0, 1, "/foo/bar.." },
	{ 0, 1, "/foo../bar" },
#endif
	{ 0, 0, ":/foo/bar" },
	{ 1, 0, ".." },
	{ 1, 0, "../" },
	{ 1, 0, "/foo/.." },
	{ 1, 0, "/foo/../" },
	{ 1, 0, "/foo/../bar" },
	{ 1, 0, "." },
	{ 1, 0, "./" },
	{ 1, 0, "/foo/." },
	{ 1, 0, "/foo/./" },
	{ 1, 0, "/foo/./bar" },
	{ 0, 1, "C:/foo/bar" },
	{ 0, 1, "D:/foo/bar" },
	{ 0, 1, "C:/foo..bar" },
	{ 0, 1, "C:/foo/bar.." },
	{ 0, 1, "C:/foo../bar" },
	{ 0, 0, "CD:/foo/bar" },
};

START_TEST(test_has_dot_component)
{
	FOREACH(a) fail_unless(has_dot_component(a[i].a)==a[i].expected_dot);
}
END_TEST

START_TEST(test_is_absolute)
{
	FOREACH(a) fail_unless(is_absolute(a[i].a)==a[i].expected_abs);
}
END_TEST

Suite *suite_pathcmp(void)
{
	Suite *s;
	TCase *tc_core;

	s=suite_create("pathcmp");

	tc_core=tcase_create("Core");

	tcase_add_test(tc_core, test_pathcmp);
	tcase_add_test(tc_core, test_pathcmp_s);
	tcase_add_test(tc_core, test_is_subdir);
	tcase_add_test(tc_core, test_has_dot_component);
	tcase_add_test(tc_core, test_is_absolute);
	suite_add_tcase(s, tc_core);

	return s;
}
