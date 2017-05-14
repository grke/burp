#include "../../test.h"
#include "../../builders/build.h"
#include "../../builders/build_file.h"
#include "../../../src/alloc.h"
#include "../../../src/async.h"
#include "../../../src/cstat.h"
#include "../../../src/fsops.h"
#include "../../../src/server/monitor/cstat.h"
#include "../../../src/server/monitor/status_server.h"

#define BASE		"utest_server_monitor_status_server"

struct data
{
	int expected;
	const char *buf;
};

static struct data p[] = {
        { 0, NULL },
        { 0, "" },
        { 0, "cntr" },
        { 0, "cntr\t" },
        { 0, "cntr\tclientname" },
        { 0, "cntr\tclientname.123\t" },
        { 0, "cntr\tclientname.123\tfield" },
        { 0, "clients" },
        { 0, "clients\t" },
        { 0, "clients\tone" },
        { 0, "clients\tone\t" },
        { 0, "clients\tone\ttwo" },
        { 0, "junkityjunk" },
};

START_TEST(test_parse_parent_data_weird)
{
	FOREACH(p)
	{
		char buf[64];
		snprintf(buf, sizeof(buf), "%s", p[i].buf);
		fail_unless(parse_parent_data(buf, NULL)==p[i].expected);
	}
	alloc_check();
}
END_TEST


static void clean(void)
{
	fail_unless(recursive_delete(BASE)==0);
	fail_unless(recursive_delete(CLIENTCONFDIR)==0);
}

static void assert_cstat_run_statuses(struct cstat *clist,
	enum run_status r1, enum run_status r2, enum run_status r3)
{
	struct cstat *cli1;
	struct cstat *cli2;
	struct cstat *cli3;
	cli1=clist;
	cli2=cli1->next;
	cli3=cli2->next;
	fail_unless(cli1->run_status==r1);
	fail_unless(cli2->run_status==r2);
	fail_unless(cli3->run_status==r3);
}

START_TEST(test_parse_parent_data)
{
	char buf[64];
	struct cstat *clist=NULL;
	const char *cnames[] = {"cli1", "cli2", "cli3", NULL};

	clean();
	build_clientconfdir_files(cnames, NULL);

	fail_unless(!cstat_get_client_names(&clist, CLIENTCONFDIR));

	assert_cstat_list(clist, cnames);
	clist->permitted=1;
	clist->next->permitted=1;
	clist->next->next->permitted=1;
	assert_cstat_run_statuses(clist,
		RUN_STATUS_UNSET, RUN_STATUS_UNSET, RUN_STATUS_UNSET);

	snprintf(buf, sizeof(buf), "clients");
	fail_unless(!parse_parent_data(buf, clist));
	assert_cstat_run_statuses(clist,
		RUN_STATUS_IDLE, RUN_STATUS_IDLE, RUN_STATUS_IDLE);

	snprintf(buf, sizeof(buf), "clients\tcli2");
	fail_unless(!parse_parent_data(buf, clist));
	assert_cstat_run_statuses(clist,
		RUN_STATUS_IDLE, RUN_STATUS_RUNNING, RUN_STATUS_IDLE);

	snprintf(buf, sizeof(buf), "clients\tcli2\tcli3");
	fail_unless(!parse_parent_data(buf, clist));
	assert_cstat_run_statuses(clist,
		RUN_STATUS_IDLE, RUN_STATUS_RUNNING, RUN_STATUS_RUNNING);

	snprintf(buf, sizeof(buf), "clients");
	fail_unless(!parse_parent_data(buf, clist));
	assert_cstat_run_statuses(clist,
		RUN_STATUS_IDLE, RUN_STATUS_IDLE, RUN_STATUS_IDLE);

	snprintf(buf, sizeof(buf), "cntr\tcli2.123\tblah");
	fail_unless(!parse_parent_data(buf, clist));
	assert_cstat_run_statuses(clist,
		RUN_STATUS_IDLE, RUN_STATUS_RUNNING, RUN_STATUS_IDLE);

	cstat_list_free(&clist);
	clean();
	alloc_check();
}
END_TEST

static void do_test_extract_client_and_pid(char *buf,
	const char *expected_cname, int expected_pid)
{
	int pid=-1;
	char b[32]="";
	char *cname=NULL;
	snprintf(b, sizeof(b), "%s", buf);
	fail_unless(!extract_client_and_pid(b, &cname, &pid));
	fail_unless(!strcmp(cname, expected_cname));
	fail_unless(pid==expected_pid);
	free_w(&cname);
	alloc_check();
}

START_TEST(test_extract_client_and_pid)
{
	do_test_extract_client_and_pid("", "", -1);
	do_test_extract_client_and_pid("cliX.12345", "cliX", 12345);
	do_test_extract_client_and_pid("cliX.12345\tblah", "cliX", 12345);
	do_test_extract_client_and_pid("cliX", "cliX", -1);
}
END_TEST

Suite *suite_server_monitor_status_server(void)
{
	Suite *s;
	TCase *tc_core;

	s=suite_create("server_monitor_status_server");

	tc_core=tcase_create("Core");
	tcase_set_timeout(tc_core, 5);

	tcase_add_test(tc_core, test_parse_parent_data_weird);
	tcase_add_test(tc_core, test_parse_parent_data);
	tcase_add_test(tc_core, test_extract_client_and_pid);

	suite_add_tcase(s, tc_core);

	return s;
}
