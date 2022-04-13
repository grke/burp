#include "../../test.h"
#include "../../builders/build.h"
#include "../../prng.h"
#include "../../../src/base64.h"
#include "../../../src/fsops.h"
#include "../../../src/hexmap.h"
#include "../../../src/server/manio.h"
#include "../../../src/server/monitor/cache.h"
#include "../../../src/server/sdirs.h"
#include "../../../src/slist.h"
#include "../../builders/build_asfd_mock.h"

#define BASE		"utest_server_monitor_cache"
#define CLIENTNAME	"utestclient"

static void do_sdirs_init(struct sdirs *sdirs)
{
	fail_unless(!sdirs_init(sdirs,
		BASE, // directory
		CLIENTNAME,
		NULL, // client_lockdir
		"a_group", // dedup_group
		NULL // manual_delete
       ));
}

static void tear_down(struct sdirs **sdirs)
{
	sdirs_free(sdirs);
	fail_unless(!recursive_delete(BASE));
	alloc_check();
}

static struct sdirs *setup(void)
{
	struct sdirs *sdirs;
	prng_init(0);
	base64_init();
	hexmap_init();
	fail_unless(!recursive_delete(BASE));
	fail_unless((sdirs=sdirs_alloc())!=NULL);
	do_sdirs_init(sdirs);
	return sdirs;
}

START_TEST(test_server_monitor_cache)
{
	struct sbuf *sb;
	struct sdirs *sdirs;
	struct slist *slist;
	struct manio *manio;
	unsigned long bno=5;

	sdirs=setup();
	slist=build_manifest(sdirs->manifest,
		/*manio_enties*/20, /*phase*/0);
        fail_unless((manio=manio_open(sdirs->manifest, "rb"))!=NULL);
        fail_unless((sb=sbuf_alloc())!=NULL);

	fail_unless(!cache_loaded(CLIENTNAME, bno));
	fail_unless(!cache_load(manio, sb, CLIENTNAME, bno));
	fail_unless(cache_loaded(CLIENTNAME, bno));
	fail_unless(!cache_loaded(CLIENTNAME, bno+1));
// FIX THIS: do an actual lookup.
//	fail_unless(cache_lookup("/"));
	cache_free();
	fail_unless(!cache_loaded(CLIENTNAME, bno));

	manio_close(&manio);
	sbuf_free(&sb);
	slist_free(&slist);
	tear_down(&sdirs);
}
END_TEST

Suite *suite_server_monitor_cache(void)
{
	Suite *s;
	TCase *tc_core;

	s=suite_create("server_monitor_cache");

	tc_core=tcase_create("Core");
	tcase_set_timeout(tc_core, 5);

	tcase_add_test(tc_core, test_server_monitor_cache);

	suite_add_tcase(s, tc_core);

	return s;
}
