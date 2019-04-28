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

struct cmd_data
{
	const char *buf;
	char *command;
	char *client;
	char *backup;
	char *logfile;
	char *browse;
};

static struct cmd_data d[] = {
	{ "j:somecmd",
		"somecmd", NULL, NULL, NULL, NULL },
	{ "c:testclient:b:4",
		NULL, "testclient", "4", NULL, NULL },
	{ "c:testclient:b:4:l:blah",
		NULL, "testclient", "4", "blah", NULL },
	{ "c:testclient:b:4:l:blah:p:C:some/path",
		NULL, "testclient", "4", "blah", "C:some/path" },
	{ "c:testclient:b:4:l:blah:p:",
		NULL, "testclient", "4", "blah", "" },
	{ "c:testclient:b:4:l:blah:p",
		NULL, "testclient", "4", "blah", NULL },
};

START_TEST(test_status_server_parse_cmd)
{
	FOREACH(d)
	{
		char *command=NULL;
		char *client=NULL;
		char *backup=NULL;
		char *logfile=NULL;
		char *browse=NULL;

		fail_unless(status_server_parse_cmd(
			d[i].buf,
			&command,
			&client,
			&backup,
			&logfile,
			&browse
		)==0);

		if(d[i].command) fail_unless(!strcmp(command, d[i].command));
		else fail_unless(command==NULL);
		if(d[i].client) fail_unless(!strcmp(client, d[i].client));
		else fail_unless(client==NULL);
		if(d[i].backup) fail_unless(!strcmp(backup, d[i].backup));
		else fail_unless(backup==NULL);
		if(d[i].logfile) fail_unless(!strcmp(logfile, d[i].logfile));
		else fail_unless(logfile==NULL);
		if(d[i].browse) fail_unless(!strcmp(browse, d[i].browse));
		else fail_unless(browse==NULL);

		free_w(&command);
		free_w(&client);
		free_w(&backup);
		free_w(&logfile);
		free_w(&browse);
		alloc_check();
	}
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
	tcase_add_test(tc_core, test_status_server_parse_cmd);

	suite_add_tcase(s, tc_core);

	return s;
}
