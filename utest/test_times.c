#include "test.h"
#include "../src/alloc.h"
#include "../src/times.h"

static char *setup_tz(const char *offset)
{
	char *tz=NULL;
#ifndef HAVE_WIN32
	if((tz=getenv("TZ")))
		fail_unless((tz=strdup_w(tz, __func__))!=NULL);
	setenv("TZ", offset, 1);
#endif
	return tz;
}

static void tear_down_tz(char **tz)
{
#ifndef HAVE_WIN32
	if(tz && *tz)
	{
		setenv("TZ", *tz, 1);
		free_w(tz);
	}
	else
		unsetenv("TZ");
#endif
}

struct ds
{
        time_t t;
	const char *tz;
	const char *str;
};

static struct ds ds[] = {
	{ 0, "", "never" },
#ifdef __GLIBC__
	{ 1000, "", "1970-01-01 00:16:40 +0000" },
	{ 1000, "UTC+10", "1969-12-31 14:16:40 -1000" },
	{ 1000, "UTC+10", "1969-12-31 14:16:40 -1000" },
#else
	// Only glibc supports %z in strptime.
	{ 1000, "", "1970-01-01 00:16:40" },
#endif
};

START_TEST(test_getdatestr)
{
	FOREACH(ds)
	{
		char *tz;
		const char *str;
		tz=setup_tz(ds[i].tz);
		str=getdatestr(ds[i].t);
		fail_unless(!strcmp(ds[i].str, str));
		tear_down_tz(&tz);
		alloc_check();
	}
}
END_TEST

Suite *suite_times(void)
{
	Suite *s;
	TCase *tc_core;

	s=suite_create("times");

	tc_core=tcase_create("Core");

	tcase_add_test(tc_core, test_getdatestr);
	suite_add_tcase(s, tc_core);

	return s;
}
