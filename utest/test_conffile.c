#include <check.h>
#include <stdio.h>
#include <stdlib.h>
#include "../src/conffile.h"

struct data
{
        const char *str;
	const char *field;
	const char *value;
};

static struct data d[] = {
	{ "a=b", "a", "b" },
	{ "a = b", "a", "b" },
	{ "   a  =    b ", "a", "b" },
	{ "   a  =    b \n", "a", "b" },
	{ "#a=b", NULL, NULL },
	{ "  #a=b", NULL, NULL },
	{ "a='b'", "a", "b" },
	{ "a='b", "a", "b" },
	{ "a=b'", "a", "b'" },
	{ "a=\"b\"", "a", "b" },
	{ "a=b\"", "a", "b\"" },
	{ "a=\"b", "a", "b" },
	{ "a=b # comment", "a", "b # comment" }, // Maybe fix this.
	{ "field=longvalue with spaces", "field", "longvalue with spaces" },
};

START_TEST(test_conf_get_pair)
{
        unsigned int i;
        for(i=0; i<sizeof(d)/sizeof(*d); i++)
	{
		char *field=NULL;
		char *value=NULL;
		char *str=strdup(d[i].str);
		conf_get_pair(str, &field, &value);
		if(!field || !d[i].field)
			ck_assert_int_eq(field==d[i].field, 1);
		else
			ck_assert_int_eq(!strcmp(field, d[i].field), 1);
		if(!value || !d[i].value)
			ck_assert_int_eq(value==d[i].value, 1);
		else
			ck_assert_int_eq(!strcmp(value, d[i].value), 1);
		free(str);
	}
}
END_TEST


Suite *suite_conffile(void)
{
	Suite *s;
	TCase *tc_core;

	s=suite_create("conffile");

	tc_core=tcase_create("Core");

	tcase_add_test(tc_core, test_conf_get_pair);
	suite_add_tcase(s, tc_core);

	return s;
}
