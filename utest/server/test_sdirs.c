#include "../test.h"
#include "../../src/alloc.h"
#include "../../src/conf.h"
#include "../../src/conffile.h"
#include "../../src/fsops.h"
#include "../../src/lock.h"
#include "../../src/prepend.h"
#include "../../src/server/protocol1/fdirs.h"
#include "../../src/server/sdirs.h"
#include "../../src/server/timestamp.h"
#include "../../src/times.h"

#define BASE		"utest_sdirs"

static struct sdirs *setup(void)
{
	struct sdirs *sdirs;
	fail_unless(recursive_delete(BASE)==0);
	fail_unless((sdirs=sdirs_alloc())!=NULL);
	return sdirs;
}

static void tear_down(struct sdirs **sdirs)
{
	sdirs_free(sdirs);
	fail_unless(recursive_delete(BASE)==0);
	alloc_check();
}

static void do_sdirs_init(struct sdirs *sdirs, enum protocol protocol,
	const char *client_lockdir)
{
	fail_unless(!sdirs_init(sdirs, protocol,
		BASE, // directory
		"utestclient", // cname
		client_lockdir,
		"a_group", // dedup_group
		NULL // manual_delete
		));
}

static void check_dynamic_paths(struct sdirs *sdirs, enum protocol protocol,
	const char *manifest)
{
	char tstmp[128]="";
	char *rworking=NULL;
	char *rmanifest=NULL;
	char *treepath=NULL;
	char *relink=NULL;

	fail_unless(sdirs->rworking==NULL);
	fail_unless(sdirs->rmanifest==NULL);
	fail_unless(sdirs->treepath==NULL);
	fail_unless(sdirs->relink==NULL);

	fail_unless(sdirs_create_real_working(sdirs, 1,
		DEFAULT_TIMESTAMP_FORMAT)==0);
	fail_unless(sdirs_get_real_manifest(sdirs, protocol)==0);
	fail_unless(timestamp_read(sdirs->timestamp, tstmp, sizeof(tstmp))==0);
	rworking=prepend_s(sdirs->client, tstmp);
	ck_assert_str_eq(sdirs->rworking, rworking);
	treepath=prepend_s(rworking, "data/t");
	ck_assert_str_eq(sdirs->treepath, treepath);
	rmanifest=prepend_s(rworking, manifest);
	ck_assert_str_eq(sdirs->rmanifest, rmanifest);
	relink=prepend_s(rworking, "relink");
	ck_assert_str_eq(sdirs->relink, relink);

	free_w(&sdirs->rworking);
	free_w(&sdirs->treepath);
	free_w(&sdirs->relink);

	fail_unless(sdirs_get_real_working_from_symlink(sdirs)==0);
	ck_assert_str_eq(sdirs->rworking, rworking);
	ck_assert_str_eq(sdirs->treepath, treepath);
	ck_assert_str_eq(sdirs->relink, relink);
	
	free_w(&rworking);
	free_w(&rmanifest);
	free_w(&treepath);
	free_w(&relink);
}

#define CLIENT		BASE "/utestclient"
#define WORKING		CLIENT "/working"
#define CURRENT		CLIENT "/current"

static void protocol1_tests(struct sdirs *sdirs)
{
	do_sdirs_init(sdirs, PROTO_1, NULL /* client_lockdir */);
	ck_assert_str_eq(sdirs->base, BASE);
	fail_unless(sdirs->dedup==NULL);
	fail_unless(sdirs->champlock==NULL);
	fail_unless(sdirs->champsock==NULL);
	fail_unless(sdirs->champlog==NULL);
	fail_unless(sdirs->champ_dindex_lock==NULL);
	fail_unless(sdirs->data==NULL);
	ck_assert_str_eq(sdirs->clients, BASE);
	ck_assert_str_eq(sdirs->client, CLIENT);
	ck_assert_str_eq(sdirs->created, CLIENT "/.created");
	ck_assert_str_eq(sdirs->command, CLIENT "/.command");
	ck_assert_str_eq(sdirs->working, WORKING);
	ck_assert_str_eq(sdirs->finishing, CLIENT "/finishing");
	ck_assert_str_eq(sdirs->current, CLIENT "/current");
	ck_assert_str_eq(sdirs->currenttmp, CLIENT "/current.tmp");
	ck_assert_str_eq(sdirs->deleteme, CLIENT "/deleteme");
	ck_assert_str_eq(sdirs->timestamp, WORKING "/timestamp");
	ck_assert_str_eq(sdirs->changed, WORKING "/changed");
	ck_assert_str_eq(sdirs->unchanged, WORKING "/unchanged");
	ck_assert_str_eq(sdirs->manifest, WORKING "/manifest.gz");
	ck_assert_str_eq(sdirs->cmanifest, CURRENT "/manifest.gz");
	ck_assert_str_eq(sdirs->phase1data, WORKING "/phase1.gz");
	ck_assert_str_eq(sdirs->lockdir, CLIENT);
	ck_assert_str_eq(sdirs->lock_storage_for_write->path,
		CLIENT "/lockfile");
	ck_assert_str_eq(sdirs->currentdata, CURRENT "/" DATA_DIR);
	ck_assert_str_eq(sdirs->datadirtmp, WORKING "/data.tmp");
	ck_assert_str_eq(sdirs->cincexc, CURRENT "/incexc");
	ck_assert_str_eq(sdirs->deltmppath, WORKING "/deltmppath");

	check_dynamic_paths(sdirs, PROTO_1, "manifest.gz");
}

#define DEDUP		BASE "/a_group"
#define DATA		DEDUP "/data"
#define CLIENTS		DEDUP "/clients"
#define CLIENT2		CLIENTS "/utestclient"
#define WORKING2	CLIENT2 "/working"
#define CURRENT2	CLIENT2 "/current"

static void protocol2_tests(struct sdirs *sdirs)
{
	do_sdirs_init(sdirs, PROTO_2, NULL /* client_lockdir */);
	ck_assert_str_eq(sdirs->base, BASE);
	ck_assert_str_eq(sdirs->dedup, DEDUP);
	ck_assert_str_eq(sdirs->champlock, DATA "/cc.lock");
	ck_assert_str_eq(sdirs->champsock, DATA "/cc.sock");
	ck_assert_str_eq(sdirs->champlog, DATA "/cc.log");
	ck_assert_str_eq(sdirs->champ_dindex_lock, DATA "/dindex.lock");
	ck_assert_str_eq(sdirs->data, DATA);
	ck_assert_str_eq(sdirs->clients, CLIENTS);
	ck_assert_str_eq(sdirs->client, CLIENT2);
	ck_assert_str_eq(sdirs->created, CLIENT2 "/.created");
	ck_assert_str_eq(sdirs->command, CLIENT2 "/.command");
	ck_assert_str_eq(sdirs->working, WORKING2);
	ck_assert_str_eq(sdirs->finishing, CLIENT2 "/finishing");
	ck_assert_str_eq(sdirs->current, CLIENT2 "/current");
	ck_assert_str_eq(sdirs->currenttmp, CLIENT2 "/current.tmp");
	ck_assert_str_eq(sdirs->deleteme, CLIENT2 "/deleteme");
	ck_assert_str_eq(sdirs->dindex, CLIENT2 "/dindex");
	ck_assert_str_eq(sdirs->dfiles, CLIENT2 "/dfiles");
	ck_assert_str_eq(sdirs->cfiles, DATA "/cfiles");
	ck_assert_str_eq(sdirs->global_sparse, DATA "/sparse");
	ck_assert_str_eq(sdirs->timestamp, WORKING2 "/timestamp");
	ck_assert_str_eq(sdirs->changed, WORKING2 "/changed");
	ck_assert_str_eq(sdirs->unchanged, WORKING2 "/unchanged");
	ck_assert_str_eq(sdirs->manifest, WORKING2 "/manifest");
	ck_assert_str_eq(sdirs->cmanifest, CURRENT2 "/manifest");
	ck_assert_str_eq(sdirs->phase1data, WORKING2 "/phase1.gz");
	ck_assert_str_eq(sdirs->lockdir, CLIENT2);
	ck_assert_str_eq(sdirs->lock_storage_for_write->path,
		CLIENT2 "/lockfile");
	fail_unless(sdirs->currentdata==NULL);
	fail_unless(sdirs->datadirtmp==NULL);
	fail_unless(sdirs->cincexc==NULL);
	fail_unless(sdirs->deltmppath==NULL);

	check_dynamic_paths(sdirs, PROTO_2, "manifest");
}

START_TEST(test_sdirs)
{
	struct sdirs *sdirs;
	sdirs=setup();

	protocol1_tests(sdirs);
	sdirs_free_content(sdirs);
	protocol2_tests(sdirs);

	tear_down(&sdirs);
}
END_TEST

START_TEST(test_lockdirs)
{
	struct sdirs *sdirs;
	sdirs=setup();
	do_sdirs_init(sdirs, PROTO_2, "/some/other/dir" /* client_lockdir */);
	ck_assert_str_eq(sdirs->lock_storage_for_write->path,
		"/some/other/dir/utestclient/lockfile");

	tear_down(&sdirs);
}
END_TEST

Suite *suite_server_sdirs(void)
{
	Suite *s;
	TCase *tc_core;

	s=suite_create("server_sdirs");

	tc_core=tcase_create("Core");

	tcase_add_test(tc_core, test_sdirs);
	tcase_add_test(tc_core, test_lockdirs);
	suite_add_tcase(s, tc_core);

	return s;
}
