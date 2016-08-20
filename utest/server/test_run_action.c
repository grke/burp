#include "utest/test.h"
#include "action.h"
#include "alloc.h"
#include "conf.h"
#include "server/run_action.h"

struct parsedata
{
	const char *str;
	enum action act;
	const char *backupnostr;
	const char *restoreregex;
	int ret;
};

static struct parsedata pd[] = {
	{ "restore 1:regex", ACTION_RESTORE, "1", "regex", 0 },
	{ "restore 2:", ACTION_RESTORE, "2", NULL, 0 },
	{ "restore 3", ACTION_RESTORE, "3", NULL, 0 },
	{ "verify 1:regex", ACTION_VERIFY, "1", "regex", 0 },
	{ "verify 2:", ACTION_VERIFY, "2", NULL, 0 },
	{ "verify 3", ACTION_VERIFY, "3", NULL, 0 },
	{ "backup 3", (enum action)0, NULL, NULL, -1 },
	{ "restore1:regex", (enum action)0, NULL, NULL, -1 },
	{ "", (enum action)0, NULL, NULL, -1 },
	{ NULL, (enum action)0, NULL, NULL, -1 },
};

static void run_test(struct parsedata *p)
{
	int ret;
	enum action act;
	struct conf **confs=NULL;
	confs=confs_alloc();
	confs_init(confs);

	ret=parse_restore_str_and_set_confs(p->str, &act, confs);
	fail_unless(ret==p->ret);
	if(!ret)
	{
		const char *backupnostr=NULL;
		const char *restoreregex=NULL;
		fail_unless(act==p->act);
		backupnostr=get_string(confs[OPT_BACKUP]);
		restoreregex=get_string(confs[OPT_REGEX]);
		fail_unless(!strcmp(backupnostr, p->backupnostr));
		if(!p->restoreregex)
			fail_unless(restoreregex==NULL);
		else
			fail_unless(!strcmp(restoreregex, p->restoreregex));
	}

	confs_free(&confs);
	alloc_check();
}

START_TEST(test_parse_restore_str_and_set_confs)
{
	FOREACH(pd)
	{
		run_test(&pd[i]);
	}
}
END_TEST

Suite *suite_server_run_action(void)
{
	Suite *s;
	TCase *tc_core;

	s=suite_create("server_run_action");

	tc_core=tcase_create("Core");
	tcase_add_test(tc_core, test_parse_restore_str_and_set_confs);

	suite_add_tcase(s, tc_core);

	return s;
}
