#include "utest/test.h"
#include "utest/builders/build.h"
#include "alloc.h"
#include "bu.h"
#include "cstat.h"
#include "fsops.h"
#include "server/bu_get.h"
#include "server/monitor/browse.h"
#include "server/monitor/cache.h"
#include "server/monitor/cstat.h"
#include "server/sdirs.h"

#define BASE		"utest_server_monitor_browse"
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

static struct sd sd1[] = {
        { "0000001 1970-01-01 00:00:00", 1, 1, BU_DELETABLE|BU_CURRENT },
};

static void run_test(enum protocol protocol, int use_cache)
{
	struct cstat *cstat;
	cstat=setup_cstat(CNAME, protocol);
	build_storage_dirs((struct sdirs *)cstat->sdirs,
		sd1, ARR_LEN(sd1));
	cstat->permitted=1;
	fail_unless(!cstat_set_backup_list(cstat));
	fail_unless(!browse_manifest(
		cstat,
		cstat->bu,
		NULL, // browse
		use_cache));
	if(use_cache) cache_free();
	tear_down(&cstat);
}

START_TEST(test_server_monitor_browse)
{
	run_test(PROTO_1, 0 /* use_cache */);
	run_test(PROTO_2, 0 /* use_cache */);
//	run_test(PROTO_1, 1 /* use_cache */);
//	run_test(PROTO_2, 1 /* use_cache */);
}
END_TEST

Suite *suite_server_monitor_browse(void)
{
	Suite *s;
	TCase *tc_core;

	s=suite_create("server_monitor_browse");

	tc_core=tcase_create("Core");

	tcase_add_test(tc_core, test_server_monitor_browse);
	suite_add_tcase(s, tc_core);

	return s;
}
