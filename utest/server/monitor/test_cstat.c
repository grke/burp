#include "../../test.h"
#include "../../builders/build.h"
#include "../../builders/build_file.h"
#include "../../../src/alloc.h"
#include "../../../src/bu.h"
#include "../../../src/cstat.h"
#include "../../../src/conf.h"
#include "../../../src/conffile.h"
#include "../../../src/fsops.h"
#include "../../../src/lock.h"
#include "../../../src/server/monitor/cstat.h"
#include "../../../src/server/sdirs.h"

#define BASE		"utest_server_monitor_cstat"
#define CLIENTCONFDIR	"clientconfdir"
#define GLOBAL_CONF	BASE "/burp-server.conf"
#define CNAME		"utestclient"

static void clean(void)
{
	fail_unless(recursive_delete(BASE)==0);
	fail_unless(recursive_delete(CLIENTCONFDIR)==0);
	fail_unless(recursive_delete(GLOBAL_CONF)==0);
}

static struct sdirs *setup_sdirs(enum protocol protocol)
{
	struct sdirs *sdirs;
	fail_unless((sdirs=sdirs_alloc())!=NULL);
	fail_unless(!sdirs_init(sdirs, protocol,
		BASE, // directory
		CNAME, // cname
		NULL, // client_lockdir
		"a_group", // dedup_group
		NULL // manual_delete
	));
	return sdirs;
}

static struct cstat *setup_cstat(const char *cname, enum protocol protocol)
{
	struct cstat *cstat;
	struct sdirs *sdirs;
	clean();
	sdirs=setup_sdirs(protocol);
	fail_unless((cstat=cstat_alloc())!=NULL);
	fail_unless(!cstat_init(cstat, cname, CLIENTCONFDIR));
	cstat->sdirs=sdirs;
	return cstat;
}

static void tear_down(struct cstat **cstat)
{
	sdirs_free((struct sdirs **)&(*cstat)->sdirs);
	cstat_free(cstat);
	alloc_check();
	clean();
}

static struct sd sd123[] = {
	{ "0000001 1970-01-01 00:00:00", 1, 1, BU_DELETABLE },
	{ "0000002 1970-01-02 00:00:00", 2, 2, 0 },
	{ "0000003 1970-01-03 00:00:00", 3, 3, BU_CURRENT }
};

static struct sd sd13[] = {
	{ "0000001 1970-01-01 00:00:00", 1, 1, BU_DELETABLE },
	{ "0000003 1970-01-03 00:00:00", 3, 3, BU_CURRENT }
};

static struct sd sd12345[] = {
	{ "0000001 1970-01-01 00:00:00", 1, 1, BU_DELETABLE },
	{ "0000002 1970-01-02 00:00:00", 2, 2, 0 },
	{ "0000003 1970-01-03 00:00:00", 3, 3, 0 },
	{ "0000004 1970-01-04 00:00:00", 4, 4, 0 },
	{ "0000005 1970-01-05 00:00:00", 5, 5, BU_CURRENT }
};

static void do_test_cstat_set_backup_list(enum protocol protocol)
{
	struct cstat *cstat;
	cstat=setup_cstat(CNAME, protocol);
	ck_assert_str_eq(CLIENTCONFDIR "/" CNAME, cstat->conffile);

	cstat->permitted=1;

	fail_unless(recursive_delete(BASE)==0);
	build_storage_dirs((struct sdirs *)cstat->sdirs,
		sd123, ARR_LEN(sd123));
	fail_unless(!cstat_set_backup_list(cstat));
	fail_unless(cstat->bu!=NULL);

	fail_unless(recursive_delete(BASE)==0);
	build_storage_dirs((struct sdirs *)cstat->sdirs,
		sd13, ARR_LEN(sd13));
	fail_unless(!cstat_set_backup_list(cstat));
	fail_unless(cstat->bu!=NULL);

	fail_unless(recursive_delete(BASE)==0);
	build_storage_dirs((struct sdirs *)cstat->sdirs,
		sd12345, ARR_LEN(sd12345));
	fail_unless(!cstat_set_backup_list(cstat));
	fail_unless(cstat->bu!=NULL);

	cstat->permitted=0;
	fail_unless(!cstat_set_backup_list(cstat));
	fail_unless(cstat->bu==NULL);

	tear_down(&cstat);
}

START_TEST(test_cstat_set_backup_list)
{
	do_test_cstat_set_backup_list(PROTO_1);
	do_test_cstat_set_backup_list(PROTO_2);
}
END_TEST

START_TEST(test_cstat_set_backup_list_fail_bu_get_list)
{
	struct cstat *cstat;
	fail_unless((cstat=cstat_alloc())!=NULL);
	cstat->permitted=1;
	// No sdirs is set on cstat, so bu_get_list_with_working() will fail.
	// But cstat_set_backup_list() will return OK anyway.
	fail_unless(!cstat_set_backup_list(cstat));
	fail_unless(cstat->bu==NULL);
	tear_down(&cstat);
}
END_TEST

START_TEST(test_cstat_get_client_names)
{
	struct cstat *clist=NULL;
	const char *cnames[] =
		{"cli1", "cli2", "cli3", NULL};
	const char *cnames_add[] =
		{"cli0", "cli1", "cli2", "cli2a", "cli3", "cli4", NULL};
	const char *cnames_rm[] =
		{"cli2", NULL};
	const char *tmp_files[] =
		{".abc", "xyz~", NULL };

	clean();
	build_clientconfdir_files(cnames, NULL);
	fail_unless(!cstat_get_client_names(&clist, CLIENTCONFDIR));
	assert_cstat_list(clist, cnames);

	// Call again with the same clientconfdir files.
	clean();
	build_clientconfdir_files(cnames, NULL);
	fail_unless(!cstat_get_client_names(&clist, CLIENTCONFDIR));
	assert_cstat_list(clist, cnames);

	// Call again with extra clientconfdir files.
	clean();
	build_clientconfdir_files(cnames_add, NULL);
	fail_unless(!cstat_get_client_names(&clist, CLIENTCONFDIR));
	assert_cstat_list(clist, cnames_add);

	// Call again with fewer clientconfdir files.
	// The list will not be shorter.
	clean();
	build_clientconfdir_files(cnames_rm, NULL);
	fail_unless(!cstat_get_client_names(&clist, CLIENTCONFDIR));
	assert_cstat_list(clist, cnames_add);

	// Temporary files should be missed.
	clean();
	build_clientconfdir_files(tmp_files, NULL);
	fail_unless(!cstat_get_client_names(&clist, CLIENTCONFDIR));
	assert_cstat_list(clist, cnames_add);

	// Cause an error.
	clean();
	fail_unless(cstat_get_client_names(&clist, CLIENTCONFDIR)==-1);

	cstat_list_free(&clist);
	clean();
	alloc_check();
}
END_TEST

static void cstat_list_free_sdirs(struct cstat *clist)
{
	struct cstat *c;
	for(c=clist; c; c=c->next)
		sdirs_free((struct sdirs **)&c->sdirs);
}

static void set_mtime(const char *file, int diff)
{
	time_t t;
	char path[256];
	struct utimbuf times;

	t=time(NULL);
	t+=diff;
	times.actime=t;
	times.modtime=t;
	snprintf(path, sizeof(path), CLIENTCONFDIR "/%s", file);
	fail_unless(!utime(path, &times));
}

static void set_mtimes(const char *cnames[], int diff)
{
	int i=0;
	for(i=0; cnames[i]; i++)
		set_mtime(cnames[i], diff);
}

START_TEST(test_cstat_reload_from_client_confs)
{
	struct cstat *clist=NULL;
	struct conf **monitor_cconfs;
	struct conf **globalcs;
	struct conf **cconfs;
	const char *cnames1[] = {"cli1", NULL};
	const char *cnames123[] = {"cli1", "cli2", "cli3", NULL};
	const char *cnames13[] = {"cli1", "cli3", NULL};

	clean();
	fail_unless((monitor_cconfs=confs_alloc())!=NULL);
	fail_unless((globalcs=confs_alloc())!=NULL);
	fail_unless((cconfs=confs_alloc())!=NULL);
	fail_unless(!confs_init(monitor_cconfs));
	fail_unless(!confs_init(globalcs));
	build_file(GLOBAL_CONF, MIN_SERVER_CONF);
	fail_unless(!conf_load_global_only(GLOBAL_CONF, monitor_cconfs));
	fail_unless(!conf_load_global_only(GLOBAL_CONF, globalcs));
	build_clientconfdir_files(cnames123, NULL);

	fail_unless(!cstat_get_client_names(&clist, CLIENTCONFDIR));
	fail_unless(cstat_reload_from_client_confs(&clist, monitor_cconfs,
		globalcs, cconfs)==3);
	assert_cstat_list(clist, cnames123);

	// Going again should result in 0 updates.
	fail_unless(!cstat_get_client_names(&clist, CLIENTCONFDIR));
	fail_unless(cstat_reload_from_client_confs(&clist, monitor_cconfs,
		globalcs, cconfs)==0);
	assert_cstat_list(clist, cnames123);

	// Touching all clientconfdir files should result in 3 updates.
	set_mtimes(cnames123, -100);
	fail_unless(!cstat_get_client_names(&clist, CLIENTCONFDIR));
	fail_unless(cstat_reload_from_client_confs(&clist, monitor_cconfs,
		globalcs, cconfs)==3);
	assert_cstat_list(clist, cnames123);

	// Touching one clientconfdir file should result in 1 update.
	set_mtimes(cnames1, -200);
	fail_unless(cstat_reload_from_client_confs(&clist, monitor_cconfs,
		globalcs, cconfs)==1);
	assert_cstat_list(clist, cnames123);

	// Deleting one clientconfdir file should result in 0 updates.
	delete_clientconfdir_file("cli2");
	fail_unless(cstat_reload_from_client_confs(&clist, monitor_cconfs,
		globalcs, cconfs)==0);
	assert_cstat_list(clist, cnames13);

	// A clientconfdir file with junk in it should get permission denied
	// and remain in the list.
	build_file(get_clientconfdir_path("cli1"), "klasdjldkjf");
	fail_unless(cstat_reload_from_client_confs(&clist, monitor_cconfs,
		globalcs, cconfs)==0);
	assert_cstat_list(clist, cnames13);
	// Should not reload it next time round.
	fail_unless(cstat_reload_from_client_confs(&clist, monitor_cconfs,
		globalcs, cconfs)==0);
	assert_cstat_list(clist, cnames13);
	// Fix the file, and we should reload it.
	build_file(get_clientconfdir_path("cli1"), NULL);
	set_mtimes(cnames1, -300);
	fail_unless(cstat_reload_from_client_confs(&clist, monitor_cconfs,
		globalcs, cconfs)==1);
	assert_cstat_list(clist, cnames13);

	// Delete everything.
	delete_clientconfdir_file("cli1");
	delete_clientconfdir_file("cli3");
	fail_unless(cstat_reload_from_client_confs(&clist, monitor_cconfs,
		globalcs, cconfs)==0);
	assert_cstat_list(clist, NULL);

	unlink(GLOBAL_CONF);
	fail_unless(cstat_reload_from_client_confs(&clist, monitor_cconfs,
		globalcs, cconfs)==-1);

	confs_free(&monitor_cconfs);
	confs_free(&globalcs);
	confs_free(&cconfs);
	cstat_list_free_sdirs(clist);
	cstat_list_free(&clist);
	clean();
	alloc_check();
}
END_TEST

static void setup_globalcs(struct conf ***globalcs)
{
	fail_unless((*globalcs=confs_alloc())!=NULL);
	fail_unless(!confs_init(*globalcs));
	build_file(GLOBAL_CONF, MIN_SERVER_CONF);
	fail_unless(!conf_load_global_only(GLOBAL_CONF, *globalcs));
}

static struct cstat *test_cstat_remove_setup(struct conf ***globalcs,
	const char *cnames[])
{
	struct cstat *clist=NULL;
	clean();
	setup_globalcs(globalcs);
	build_clientconfdir_files(cnames, NULL);
	fail_unless(!cstat_get_client_names(&clist, CLIENTCONFDIR));
	assert_cstat_list(clist, cnames);
	return clist;
}

static void test_cstat_remove_teardown(struct conf ***globalcs,
	struct cstat **clist)
{
	confs_free(globalcs);
	cstat_list_free_sdirs(*clist);
	cstat_list_free(clist);
	clean();
	alloc_check();
}

static const char *cnames1234[] = {"cli1", "cli2", "cli3", "cli4", NULL};

START_TEST(test_cstat_remove_first)
{
	struct cstat *c;
	struct cstat *clist=NULL;
	struct conf **globalcs;
	const char *cnames234[] = {"cli2", "cli3", "cli4", NULL};
	clist=test_cstat_remove_setup(&globalcs, cnames1234);
	c=clist;
	cstat_remove(&clist, &c);
	assert_cstat_list(clist, cnames234);
	test_cstat_remove_teardown(&globalcs, &clist);
}
END_TEST

START_TEST(test_cstat_remove_second)
{
	struct cstat *c;
	struct cstat *clist=NULL;
	struct conf **globalcs;
	const char *cnames134[] = {"cli1", "cli3", "cli4", NULL};
	clist=test_cstat_remove_setup(&globalcs, cnames1234);
	c=clist->next;
	cstat_remove(&clist, &c);
	assert_cstat_list(clist, cnames134);
	test_cstat_remove_teardown(&globalcs, &clist);
}
END_TEST

START_TEST(test_cstat_remove_third)
{
	struct cstat *c;
	struct cstat *clist=NULL;
	struct conf **globalcs;
	const char *cnames124[] = {"cli1", "cli2", "cli4", NULL};
	clist=test_cstat_remove_setup(&globalcs, cnames1234);
	c=clist->next->next;
	cstat_remove(&clist, &c);
	assert_cstat_list(clist, cnames124);
	test_cstat_remove_teardown(&globalcs, &clist);
}
END_TEST

START_TEST(test_cstat_remove_fourth)
{
	struct cstat *c;
	struct cstat *clist=NULL;
	struct conf **globalcs;
	const char *cnames123[] = {"cli1", "cli2", "cli3", NULL};
	clist=test_cstat_remove_setup(&globalcs, cnames1234);
	c=clist->next->next->next;
	cstat_remove(&clist, &c);
	assert_cstat_list(clist, cnames123);
	test_cstat_remove_teardown(&globalcs, &clist);
}
END_TEST

START_TEST(test_cstat_remove_only)
{
	struct cstat *c;
	struct cstat *clist=NULL;
	struct conf **globalcs;
	const char *cnames1[] = {"cli1", NULL};
	const char *cnames0[] = {NULL};
	clist=test_cstat_remove_setup(&globalcs, cnames1);
	c=clist;
	cstat_remove(&clist, &c);
	assert_cstat_list(clist, cnames0);
	test_cstat_remove_teardown(&globalcs, &clist);
}
END_TEST

START_TEST(test_cstat_add_out_of_order)
{
	struct cstat *clist=NULL;
	struct conf **globalcs;
	const char *cnames31204[]
		= {"cli3", "cli1", "cli2", "cli0", "cli4", NULL};
	const char *cnames01234[]
		= {"cli0", "cli1", "cli2", "cli3", "cli4", NULL};
	clean();
	fail_unless((globalcs=confs_alloc())!=NULL);
	fail_unless(!confs_init(globalcs));
	build_file(GLOBAL_CONF, MIN_SERVER_CONF);
	fail_unless(!conf_load_global_only(GLOBAL_CONF, globalcs));
	build_clientconfdir_files(cnames31204, NULL);
	fail_unless(!cstat_get_client_names(&clist, CLIENTCONFDIR));
	assert_cstat_list(clist, cnames01234);
	test_cstat_remove_teardown(&globalcs, &clist);
}
END_TEST

static struct cstat *set_run_status_setup(enum protocol protocol, int permitted)
{
	struct cstat *cstat;
	cstat=setup_cstat(CNAME, protocol);
	fail_unless(cstat->run_status==RUN_STATUS_UNSET);
	cstat->permitted=permitted;
	return cstat;
}

static void test_cstat_set_run_status_not_permitted(enum protocol protocol)
{
	struct cstat *cstat;
	cstat=set_run_status_setup(protocol, 0 /*not permitted*/);
	cstat_set_run_status(cstat, RUN_STATUS_RUNNING);
	fail_unless(cstat->run_status==RUN_STATUS_UNSET);
	tear_down(&cstat);
}

static void test_cstat_set_run_status_idle(enum protocol protocol)
{
	struct cstat *cstat;
	cstat=set_run_status_setup(protocol, 1 /*permitted*/);
	cstat_set_run_status(cstat, RUN_STATUS_IDLE);
	fail_unless(cstat->run_status==RUN_STATUS_IDLE);
	tear_down(&cstat);
}

static void test_cstat_set_run_status_running(enum protocol protocol)
{
	struct cstat *cstat;
	cstat=set_run_status_setup(protocol, 1 /*permitted*/);
	cstat_set_run_status(cstat, RUN_STATUS_RUNNING);
	fail_unless(cstat->run_status==RUN_STATUS_RUNNING);
	tear_down(&cstat);
}

START_TEST(test_cstat_set_run_status)
{
	test_cstat_set_run_status_not_permitted(PROTO_1);
	test_cstat_set_run_status_not_permitted(PROTO_2);
	test_cstat_set_run_status_idle(PROTO_1);
	test_cstat_set_run_status_idle(PROTO_2);
	test_cstat_set_run_status_running(PROTO_1);
	test_cstat_set_run_status_running(PROTO_2);
}
END_TEST

static void do_test_cstat_reload_from_client_confs(enum protocol protocol)
{
	struct cstat *c1;
	struct cstat *c2;
	struct cstat *clist=NULL;
	c1=setup_cstat("cli1", protocol);
	c2=setup_cstat("cli2", protocol);
	cstat_add_to_list(&clist, c1);
	cstat_add_to_list(&clist, c2);
	c1->permitted=1;

	// First time, nothing is reloaded.
	fail_unless(reload_from_clientdir(&clist)==0);
	fail_unless(c1->bu==NULL);
	fail_unless(c2->bu==NULL);

	// Add some storage dirs, and c1 is loaded.
	build_storage_dirs((struct sdirs *)c1->sdirs,
		sd123, ARR_LEN(sd123));
	fail_unless(reload_from_clientdir(&clist)==1);
	fail_unless(c1->bu!=NULL);
	fail_unless(c2->bu==NULL);

	// Go again, nothing should be reloaded.
	fail_unless(reload_from_clientdir(&clist)==0);

	sdirs_free((struct sdirs **)&c1->sdirs);
	sdirs_free((struct sdirs **)&c2->sdirs);
	cstat_list_free(&clist);
	clean();
	alloc_check();
}

START_TEST(test_cstat_reload_from_clientdir)
{
	do_test_cstat_reload_from_client_confs(PROTO_1);
	do_test_cstat_reload_from_client_confs(PROTO_2);
}
END_TEST

static void check_restore_clients(struct cstat *cstat,
	struct conf **monitor_cconfs, const char *restore_clients, int permitted)
{
	struct conf **cconfs=NULL;
	fail_unless((cconfs=confs_alloc())!=NULL);
	fail_unless(!confs_init(cconfs));
	fail_unless(!set_string(cconfs[OPT_CNAME], "cli1"));
	build_clientconfdir_file("cli1", restore_clients);
	fail_unless(!conf_load_clientconfdir(monitor_cconfs, cconfs));
	fail_unless(!set_string(monitor_cconfs[OPT_CNAME], "cli2"));
	fail_unless(cstat_permitted(cstat, monitor_cconfs, cconfs)==permitted);
	confs_free(&cconfs);
}

START_TEST(test_cstat_permitted)
{
	struct cstat *cstat=NULL;
	struct conf **monitor_cconfs=NULL;

	clean();
	fail_unless((cstat=cstat_alloc())!=NULL);
	fail_unless(!cstat_init(cstat, "cli1", CLIENTCONFDIR));
	fail_unless((monitor_cconfs=confs_alloc())!=NULL);
	fail_unless(!confs_init(monitor_cconfs));
	build_file(GLOBAL_CONF, MIN_SERVER_CONF);
	fail_unless(!conf_load_global_only(GLOBAL_CONF, monitor_cconfs));

	// Clients can look at themselves.
	// In this case, cli1 is 'us'.
	fail_unless(!set_string(monitor_cconfs[OPT_CNAME], "cli1"));
	fail_unless(cstat_permitted(cstat, monitor_cconfs, NULL)==1);

	// Clients using the restore_client cannot see anything but the client
	// they are pretending to be.
	// In this case, cli2 is 'us'.
	fail_unless(!set_string(monitor_cconfs[OPT_CNAME], "cli2"));
	fail_unless(!set_string(monitor_cconfs[OPT_SUPER_CLIENT], "is_set"));
	fail_unless(cstat_permitted(cstat, monitor_cconfs, NULL)==0);
	fail_unless(!set_string(monitor_cconfs[OPT_SUPER_CLIENT], NULL));

	// Clients can see another client if we are listed in its
	// restore_clients list.
	// In this case, cli2 is 'us' and we are trying to look at cli1.
	check_restore_clients(cstat, monitor_cconfs,
		"restore_client = cli3\n"
		"restore_client = cli2\n"
		"restore_client = cli4\n",
		1 /* permitted */);

	// If we are not in its list, we cannot see it.
	check_restore_clients(cstat, monitor_cconfs,
		"restore_client = cli3\n"
		"restore_client = cli4\n",
		0 /* not permitted */);

	confs_free(&monitor_cconfs);
	cstat_free(&cstat);
	clean();
	alloc_check();
}
END_TEST

START_TEST(test_cstat_load_data_from_disk)
{
	struct cstat *clist=NULL;
	struct conf **monitor_cconfs;
	struct conf **globalcs;
	struct conf **cconfs;
	setup_globalcs(&monitor_cconfs);
	clist=test_cstat_remove_setup(&globalcs, cnames1234);
	fail_unless((cconfs=confs_alloc())!=NULL);
	cstat_load_data_from_disk(&clist, monitor_cconfs, globalcs, cconfs);
	confs_free(&cconfs);
	confs_free(&monitor_cconfs);
	test_cstat_remove_teardown(&globalcs, &clist);
}
END_TEST

Suite *suite_server_monitor_cstat(void)
{
	Suite *s;
	TCase *tc_core;

	s=suite_create("server_monitor_cstat");

	tc_core=tcase_create("Core");
	tcase_set_timeout(tc_core, 5);

	tcase_add_test(tc_core, test_cstat_set_backup_list);
	tcase_add_test(tc_core, test_cstat_set_backup_list_fail_bu_get_list);
	tcase_add_test(tc_core, test_cstat_get_client_names);
	tcase_add_test(tc_core, test_cstat_reload_from_client_confs);
	tcase_add_test(tc_core, test_cstat_remove_first);
	tcase_add_test(tc_core, test_cstat_remove_second);
	tcase_add_test(tc_core, test_cstat_remove_third);
	tcase_add_test(tc_core, test_cstat_remove_fourth);
	tcase_add_test(tc_core, test_cstat_remove_only);
	tcase_add_test(tc_core, test_cstat_add_out_of_order);
	tcase_add_test(tc_core, test_cstat_set_run_status);
	tcase_add_test(tc_core, test_cstat_reload_from_clientdir);
	tcase_add_test(tc_core, test_cstat_permitted);
	tcase_add_test(tc_core, test_cstat_load_data_from_disk);

	suite_add_tcase(s, tc_core);

	return s;
}
