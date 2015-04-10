#include <check.h>
#include <stdio.h>
#include "../test.h"
#include "../../src/alloc.h"
#include "../../src/conf.h"
#include "../../src/conffile.h"
#include "../../src/lock.h"
#include "../../src/server/protocol1/fdirs.h"
#include "../../src/server/sdirs.h"

static struct conf **setup_confs(const char *conf_str)
{
	struct conf **confs;
	confs=confs_alloc();
	confs_init(confs);
	fail_unless(!conf_load_global_only_buf(conf_str, confs));
	set_string(confs[OPT_CNAME], "utestclient");
	return confs;
}

static struct sdirs *setup(struct conf **confs)
{
	struct sdirs *sdirs;
	fail_unless((sdirs=sdirs_alloc())!=NULL);
	return sdirs;
}

static void tear_down(struct sdirs **sdirs, struct conf ***confs)
{
	sdirs_free(sdirs);
	confs_free(confs);
	fail_unless(free_count==alloc_count);
}

#define BASE		"/a/directory"
#define CLIENT		BASE "/utestclient"
#define WORKING		CLIENT "/working"
#define CURRENT		CLIENT "/current"

static void protocol1_tests(struct sdirs *sdirs, struct conf **confs)
{
	set_e_protocol(confs[OPT_PROTOCOL], PROTO_1);
	fail_unless(sdirs_init(sdirs, confs)==0);
	ck_assert_str_eq(sdirs->base, BASE);
	fail_unless(sdirs->dedup==NULL);
	fail_unless(sdirs->champlock==NULL);
	fail_unless(sdirs->champsock==NULL);
	fail_unless(sdirs->champlog==NULL);
	fail_unless(sdirs->data==NULL);
	fail_unless(sdirs->clients==NULL);
	ck_assert_str_eq(sdirs->client, CLIENT);
	ck_assert_str_eq(sdirs->working, WORKING);
	fail_unless(sdirs->rworking==NULL); // FIX THIS
	ck_assert_str_eq(sdirs->finishing, CLIENT "/finishing");
	ck_assert_str_eq(sdirs->current, CLIENT "/current");
	ck_assert_str_eq(sdirs->currenttmp, CLIENT "/current.tmp");
	ck_assert_str_eq(sdirs->deleteme, CLIENT "/deleteme");
	ck_assert_str_eq(sdirs->timestamp, WORKING "/timestamp");
	ck_assert_str_eq(sdirs->changed, WORKING "/changed");
	ck_assert_str_eq(sdirs->unchanged, WORKING "/unchanged");
	ck_assert_str_eq(sdirs->manifest, WORKING "/manifest.gz");
	fail_unless(sdirs->rmanifest==NULL); // FIX THIS
	ck_assert_str_eq(sdirs->cmanifest, CURRENT "/manifest.gz");
	ck_assert_str_eq(sdirs->phase1data, WORKING "/phase1.gz");
	ck_assert_str_eq(sdirs->lockdir, CLIENT);
	ck_assert_str_eq(sdirs->lock->path, CLIENT "/lockfile");
	ck_assert_str_eq(sdirs->currentdata, CURRENT "/" DATA_DIR);
	ck_assert_str_eq(sdirs->datadirtmp, WORKING "/data.tmp");
	ck_assert_str_eq(sdirs->cincexc, CURRENT "/incexc");
	ck_assert_str_eq(sdirs->deltmppath, WORKING "/deltmppath");
	fail_unless(sdirs->treepath==NULL); // FIX THIS
}

#define DEDUP		BASE "/a_group"
#define DATA		DEDUP "/data"
#define CLIENTS		DEDUP "/clients"
#define CLIENT2		CLIENTS "/utestclient"
#define WORKING2	CLIENT2 "/working"
#define CURRENT2	CLIENT2 "/current"

static void protocol2_tests(struct sdirs *sdirs, struct conf **confs)
{
	set_e_protocol(confs[OPT_PROTOCOL], PROTO_2);
	fail_unless(sdirs_init(sdirs, confs)==0);
	ck_assert_str_eq(sdirs->base, BASE);
	ck_assert_str_eq(sdirs->dedup, DEDUP);
	ck_assert_str_eq(sdirs->champlock, DATA "/cc.lock");
	ck_assert_str_eq(sdirs->champsock, DATA "/cc.sock");
	ck_assert_str_eq(sdirs->champlog, DATA "/cc.log");
	ck_assert_str_eq(sdirs->data, DATA);
	ck_assert_str_eq(sdirs->clients, CLIENTS);
	ck_assert_str_eq(sdirs->client, CLIENT2);
	ck_assert_str_eq(sdirs->working, WORKING2);
	fail_unless(sdirs->rworking==NULL); // FIX THIS
	ck_assert_str_eq(sdirs->finishing, CLIENT2 "/finishing");
	ck_assert_str_eq(sdirs->current, CLIENT2 "/current");
	ck_assert_str_eq(sdirs->currenttmp, CLIENT2 "/current.tmp");
	ck_assert_str_eq(sdirs->deleteme, CLIENT2 "/deleteme");
	ck_assert_str_eq(sdirs->timestamp, WORKING2 "/timestamp");
	ck_assert_str_eq(sdirs->changed, WORKING2 "/changed");
	ck_assert_str_eq(sdirs->unchanged, WORKING2 "/unchanged");
	ck_assert_str_eq(sdirs->manifest, WORKING2 "/manifest");
	fail_unless(sdirs->rmanifest==NULL); // FIX THIS
	ck_assert_str_eq(sdirs->cmanifest, CURRENT2 "/manifest");
	ck_assert_str_eq(sdirs->phase1data, WORKING2 "/phase1.gz");
	ck_assert_str_eq(sdirs->lockdir, CLIENT2);
	ck_assert_str_eq(sdirs->lock->path, CLIENT2 "/lockfile");
	fail_unless(sdirs->currentdata==NULL);
	fail_unless(sdirs->datadirtmp==NULL);
	fail_unless(sdirs->cincexc==NULL);
	fail_unless(sdirs->deltmppath==NULL);
	fail_unless(sdirs->treepath==NULL);
}

START_TEST(test_sdirs)
{
	struct sdirs *sdirs;
	struct conf **confs;
	confs=setup_confs(MIN_SERVER_CONF);
	sdirs=setup(confs);

	protocol1_tests(sdirs, confs);
	sdirs_free_content(sdirs);
	protocol2_tests(sdirs, confs);

	tear_down(&sdirs, &confs);
}
END_TEST

START_TEST(test_lockdirs)
{
	struct sdirs *sdirs;
	struct conf **confs;
	confs=setup_confs(MIN_SERVER_CONF "client_lockdir=/some/other/dir\n");
	sdirs=setup(confs);
	set_e_protocol(confs[OPT_PROTOCOL], PROTO_2);
	fail_unless(sdirs_init(sdirs, confs)==0);

	ck_assert_str_eq(sdirs->lockdir, "/some/other/dir");
	ck_assert_str_eq(sdirs->lock->path,
		"/some/other/dir/utestclient/lockfile");

	tear_down(&sdirs, &confs);
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
