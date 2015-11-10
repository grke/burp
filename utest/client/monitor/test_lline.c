#include "../../test.h"
#include "../../../src/client/monitor/lline.h"

static void check_list(struct lline *list, const char *data[])
{
        int i;
        struct lline *l=NULL;
        struct lline *last=NULL;
        for(i=0, l=list; data && data[i]; l=l->next, i++)
	{
                ck_assert_str_eq(data[i], l->line);
		last=l;
	}
	for(i--, l=last; i>=0; l=l->prev, i--)
                ck_assert_str_eq(data[i], l->line);
        fail_unless(l==NULL);
}

static void add_data(struct lline **list, const char *data[])
{
	int i;
	for(i=0; data[i]; i++)
		fail_unless(!lline_add(list, (char *)data[i]));
}

START_TEST(test_lline_add)
{
	struct lline *list=NULL;
        const char *data[] = {
		"This is my first line\n",
		"This is my second line\n",
		"This is my third line\n",
		NULL
	};
	add_data(&list, data);
	check_list(list, data);
	llines_free(&list);
	alloc_check();
}
END_TEST

START_TEST(test_lline_add_error)
{
	struct lline *list=NULL;
	fail_unless(lline_add(&list, NULL)==-1);
	alloc_check();
}
END_TEST

Suite *suite_client_monitor_lline(void)
{
	Suite *s;
	TCase *tc_core;

	s=suite_create("client_monitor_lline");

	tc_core=tcase_create("Core");

	tcase_add_test(tc_core, test_lline_add);
	tcase_add_test(tc_core, test_lline_add_error);
	suite_add_tcase(s, tc_core);

	return s;
}
