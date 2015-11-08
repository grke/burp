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

START_TEST(test_cstat_alloc_and_init)
{
	struct cstat *cstat;
	cstat=setup_cstat(CNAME, PROTO_1);
	ck_assert_str_eq(CLIENTCONFDIR "/" CNAME, cstat->conffile);
	build_storage_dirs((struct sdirs *)cstat->sdirs, sd123, ARR_LEN(sd123));
	cstat->permitted=1;
	fail_unless(!cstat_set_backup_list(cstat));
	fail_unless(cstat->bu!=NULL);
	tear_down(&cstat);
}
END_TEST

Suite *suite_server_monitor_cstat(void)
{
	Suite *s;
	TCase *tc_core;

	s=suite_create("server_monitor_cstat");

	tc_core=tcase_create("Core");

	tcase_add_test(tc_core, test_cstat_alloc_and_init);
	suite_add_tcase(s, tc_core);

	return s;
}
