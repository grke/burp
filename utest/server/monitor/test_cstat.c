#include <check.h>
#include <stdint.h>
#include <stdlib.h>
#include <stdio.h>
#include "../../test.h"
#include "../../builders/build.h"
#include "../../../src/alloc.h"
#include "../../../src/bu.h"
#include "../../../src/cstat.h"
#include "../../../src/fsops.h"
#include "../../../src/server/monitor/cstat.h"
#include "../../../src/server/sdirs.h"

#define BASE		"utest_server_monitor_cstat"
#define CLIENTCONFDIR	BASE "_clientconfdir"
#define CNAME		"utestclient"

static void clean(void)
{
	fail_unless(recursive_delete(BASE)==0);
	fail_unless(recursive_delete(CLIENTCONFDIR)==0);
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

static void do_create_file(const char *path)
{
	FILE *fp;
	fail_unless(!build_path_w(path));
	fail_unless((fp=fopen(path, "wb"))!=NULL);
	fail_unless(!fclose(fp));
}

static void create_clientconfdir_file(const char *file)
{
	char path[256]="";
	snprintf(path, sizeof(path), CLIENTCONFDIR "/%s", file);
	do_create_file(path);
}


START_TEST(test_cstat_get_client_names)
{
	struct cstat *c=NULL;
	struct cstat *clist=NULL;
	clean();
	create_clientconfdir_file("client1");
	create_clientconfdir_file("client2");
	create_clientconfdir_file("client3");
	fail_unless(!cstat_get_client_names(&clist, CLIENTCONFDIR));
	c=clist;
	ck_assert_str_eq("client1", c->cname);
	c=c->next;
	ck_assert_str_eq("client2", c->cname);
	c=c->next;
	ck_assert_str_eq("client3", c->cname);
	fail_unless(c->next!=NULL);
	clean();
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
	suite_add_tcase(s, tc_core);

	return s;
}
