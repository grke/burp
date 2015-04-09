#include <check.h>
#include <stdio.h>
#include "../../test.h"
#include "../../../src/alloc.h"
#include "../../../src/conf.h"
#include "../../../src/conffile.h"
#include "../../../src/server/protocol1/fdirs.h"
#include "../../../src/server/sdirs.h"

static struct conf **setup_confs(void)
{
	struct conf **confs;
	confs=confs_alloc();
	confs_init(confs);
	fail_unless(!conf_load_global_only_buf(MIN_SERVER_CONF, confs));
	set_string(confs[OPT_CNAME], "utestclient");
	set_e_protocol(confs[OPT_PROTOCOL], PROTO_1);
	return confs;
}

static struct sdirs *setup_sdirs(struct conf **confs)
{
	struct sdirs *sdirs;
	fail_unless((sdirs=sdirs_alloc())!=NULL);
	fail_unless(sdirs_init(sdirs, confs)==0);
	return sdirs;
}

static struct fdirs *setup(struct sdirs *sdirs)
{
	struct fdirs *fdirs;
	fail_unless((fdirs=fdirs_alloc())!=NULL);
	return fdirs;
}

static void tear_down(struct fdirs **fdirs,
	struct sdirs **sdirs, struct conf ***confs)
{
	fdirs_free(fdirs);
	sdirs_free(sdirs);
	confs_free(confs);
	fail_unless(free_count==alloc_count);
}

#define CLIENTDIR	"/a/directory/utestclient"
#define FINISHING	CLIENTDIR "/finishing"
#define CURRENT		CLIENTDIR "/current"

START_TEST(test_fdirs)
{
	struct fdirs *fdirs;
	struct sdirs *sdirs;
	struct conf **confs;
	confs=setup_confs();
	sdirs=setup_sdirs(confs);
	fdirs=setup(sdirs);
	fail_unless(fdirs_init(fdirs, sdirs, "realcurrent")==0);
	ck_assert_str_eq(fdirs->manifest, FINISHING "/manifest.gz");
	ck_assert_str_eq(fdirs->deletionsfile, FINISHING "/deletions");
	ck_assert_str_eq(fdirs->datadir, FINISHING "/data");
	ck_assert_str_eq(fdirs->datadirtmp, FINISHING "/data.tmp");
	ck_assert_str_eq(fdirs->currentdup, FINISHING "/currentdup");
	ck_assert_str_eq(fdirs->currentduptmp, FINISHING "/currentdup.tmp");
	ck_assert_str_eq(fdirs->currentdupdata, FINISHING "/currentdup/data");
	ck_assert_str_eq(fdirs->timestamp, FINISHING "/timestamp");
	ck_assert_str_eq(fdirs->fullrealcurrent, CLIENTDIR "/realcurrent");
	ck_assert_str_eq(fdirs->logpath, FINISHING "/log");
	ck_assert_str_eq(fdirs->hlinked, FINISHING "/hardlinked");
	ck_assert_str_eq(fdirs->hlinkedcurrent, CURRENT "/hardlinked");

	tear_down(&fdirs, &sdirs, &confs);
}
END_TEST

Suite *suite_server_protocol1_fdirs(void)
{
	Suite *s;
	TCase *tc_core;

	s=suite_create("server_protocol1_fdirs");

	tc_core=tcase_create("Core");

	tcase_add_test(tc_core, test_fdirs);
	suite_add_tcase(s, tc_core);

	return s;
}
