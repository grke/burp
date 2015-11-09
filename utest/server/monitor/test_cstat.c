#include <check.h>
#include <stdint.h>
#include <stdlib.h>
#include <stdio.h>
#include "../../test.h"
#include "../../builders/build.h"
#include "../../../src/alloc.h"
#include "../../../src/bu.h"
#include "../../../src/cstat.h"
#include "../../../src/conf.h"
#include "../../../src/conffile.h"
#include "../../../src/fsops.h"
#include "../../../src/server/monitor/cstat.h"
#include "../../../src/server/sdirs.h"

#define BASE		"utest_server_monitor_cstat"
#define CLIENTCONFDIR	BASE "_clientconfdir"
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

START_TEST(test_cstat_set_backup_list)
{
	struct cstat *cstat;
	cstat=setup_cstat(CNAME, PROTO_1);
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
END_TEST

static void do_create_file(const char *path, const char *content)
{
	FILE *fp;
	fail_unless(!build_path_w(path));
	fail_unless((fp=fopen(path, "wb"))!=NULL);
	if(content)
		fail_unless(fprintf(fp, "%s", content)==(int)strlen(content));
	fail_unless(!fclose(fp));
}

static void create_clientconfdir_file(const char *file)
{
	char path[256]="";
	snprintf(path, sizeof(path), CLIENTCONFDIR "/%s", file);
	do_create_file(path, NULL);
}

static void create_clientconfdir_files(const char *cnames[])
{
	int i=0;
	for(i=0; cnames[i]; i++)
		create_clientconfdir_file(cnames[i]);
}

static void check_clist(struct cstat *clist, const char *cnames[])
{
	int i;
	struct cstat *c=NULL;
	for(i=0, c=clist; cnames && cnames[i]; c=c->next, i++)
		ck_assert_str_eq(cnames[i], c->name);
if(c) printf("%s\n", c->name);
	fail_unless(c==NULL);
}

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
	create_clientconfdir_files(cnames);
	fail_unless(!cstat_get_client_names(&clist, CLIENTCONFDIR));
	check_clist(clist, cnames);

	// Call again with the same clientconfdir files.
	clean();
	create_clientconfdir_files(cnames);
	fail_unless(!cstat_get_client_names(&clist, CLIENTCONFDIR));
	check_clist(clist, cnames);

	// Call again with extra clientconfdir files.
	clean();
	create_clientconfdir_files(cnames_add);
	fail_unless(!cstat_get_client_names(&clist, CLIENTCONFDIR));
	check_clist(clist, cnames_add);

	// Call again with fewer clientconfdir files.
	// The list will not be shorter.
	clean();
	create_clientconfdir_files(cnames_rm);
	fail_unless(!cstat_get_client_names(&clist, CLIENTCONFDIR));
	check_clist(clist, cnames_add);

	// Temporary files should be missed.
	clean();
	create_clientconfdir_files(tmp_files);
	fail_unless(!cstat_get_client_names(&clist, CLIENTCONFDIR));
	check_clist(clist, cnames_add);

	cstat_list_free(&clist);
	clean();
	alloc_check();
}
END_TEST

START_TEST(test_cstat_reload_from_client_confs)
{
	struct cstat *clist=NULL;
	struct conf **globalcs;
	struct conf **cconfs;
	clean();
	fail_unless((globalcs=confs_alloc())!=NULL);
	fail_unless((cconfs=confs_alloc())!=NULL);
	fail_unless(!confs_init(globalcs));
	do_create_file(GLOBAL_CONF, MIN_SERVER_CONF);
	fail_unless(!conf_load_global_only(GLOBAL_CONF, globalcs));

	// FIX THIS: Does not do much, as clist is NULL.
	fail_unless(!cstat_reload_from_client_confs(&clist, globalcs, cconfs));

	confs_free(&globalcs);
	confs_free(&cconfs);
	cstat_list_free(&clist);
	clean();
	alloc_check();
}
END_TEST

Suite *suite_server_monitor_cstat(void)
{
	Suite *s;
	TCase *tc_core;

	s=suite_create("server_monitor_cstat");

	tc_core=tcase_create("Core");

	tcase_add_test(tc_core, test_cstat_set_backup_list);
	tcase_add_test(tc_core, test_cstat_get_client_names);
	tcase_add_test(tc_core, test_cstat_reload_from_client_confs);
	suite_add_tcase(s, tc_core);

	return s;
}
