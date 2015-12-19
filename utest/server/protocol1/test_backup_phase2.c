#include "../../test.h"
#include "../../builders/build.h"
#include "../../prng.h"
#include "../../../src/alloc.h"
#include "../../../src/asfd.h"
#include "../../../src/async.h"
#include "../../../src/attribs.h"
#include "../../../src/base64.h"
#include "../../../src/hexmap.h"
#include "../../../src/fsops.h"
#include "../../../src/iobuf.h"
#include "../../../src/server/protocol1/backup_phase2.h"
#include "../../../src/server/sdirs.h"
#include "../../../src/slist.h"
#include "../../builders/build_asfd_mock.h"

#define BASE	"utest_server_protocol1_backup_phase2"

//static struct ioevent_list areads;
//static struct ioevent_list awrites;

static void do_sdirs_init(struct sdirs *sdirs)
{
	fail_unless(!sdirs_init(sdirs, PROTO_1,
		BASE, // directory
		"utestclient", // cname
		NULL, // client_lockdir
		"a_group", // dedup_group
		NULL // manual_delete
	));
}

static struct sdirs *setup_sdirs(void)
{
	struct sdirs *sdirs;
	fail_unless((sdirs=sdirs_alloc())!=NULL);
	do_sdirs_init(sdirs);
	return sdirs;
}

static struct conf **setup_conf(void)
{
	struct conf **confs=NULL;
	fail_unless((confs=confs_alloc())!=NULL);
	fail_unless(!confs_init(confs));
	return confs;
}

static struct async *setup_async(void)
{
	struct async *as;
	fail_unless((as=async_alloc())!=NULL);
	as->init(as, 0 /* estimate */);
	return as;
}

static void setup(struct async **as,
	struct sdirs **sdirs, struct conf ***confs)
{
	if(as) *as=setup_async();
	if(sdirs) *sdirs=setup_sdirs();
	if(confs) *confs=setup_conf();
	fail_unless(!recursive_delete(BASE));
}

static void tear_down(struct async **as,
	struct sdirs **sdirs, struct conf ***confs)
{
	async_free(as);
	sdirs_free(sdirs);
	confs_free(confs);
	fail_unless(!recursive_delete(BASE));
//printf("%d %d\n", alloc_count, free_count);
	alloc_check();
}

START_TEST(test_phase2_unset_as_sdirs_confs)
{
	setup(NULL, NULL, NULL);
	fail_unless(backup_phase2_server_protocol1(
		NULL, // as
		NULL, // sdirs
		NULL, // incexc
		0, // resume
		NULL // confs
	)==-1);
	tear_down(NULL, NULL, NULL);
}
END_TEST

START_TEST(test_phase2_unset_sdirs_confs)
{
	struct async *as;
	setup(&as, NULL, NULL);
	fail_unless(backup_phase2_server_protocol1(
		as,
		NULL, // sdirs
		NULL, // incexc
		0, // resume
		NULL // confs
	)==-1);
	tear_down(&as, NULL, NULL);
}
END_TEST

START_TEST(test_phase2_unset_confs)
{
	struct async *as;
	struct sdirs *sdirs;
	setup(&as, &sdirs, NULL);
	fail_unless(backup_phase2_server_protocol1(
		as,
		sdirs,
		NULL, // incexc
		0, // resume
		NULL // confs
	)==-1);
	tear_down(&as, &sdirs, NULL);
}
END_TEST

START_TEST(test_phase2_unset_sdirs)
{
	struct async *as;
	struct conf **confs;
	setup(&as, NULL, &confs);
	fail_unless(backup_phase2_server_protocol1(
		as,
		NULL, // sdirs
		NULL, // incexc
		0, // resume
		confs
	)==-1);
	tear_down(&as, NULL, &confs);
}
END_TEST

START_TEST(test_phase2_unset_asfd)
{
	struct async *as;
	struct sdirs *sdirs;
	struct conf **confs;
	setup(&as, &sdirs, &confs);
	fail_unless(backup_phase2_server_protocol1(
		as,
		sdirs,
		NULL, // incexc
		0, // resume
		confs
	)==-1);
	tear_down(&as, &sdirs, &confs);
}
END_TEST

Suite *suite_server_protocol1_backup_phase2(void)
{
	Suite *s;
	TCase *tc_core;

	s=suite_create("server_protocol1_backup_phase2");

	tc_core=tcase_create("Core");
	tcase_set_timeout(tc_core, 60);

	tcase_add_test(tc_core, test_phase2_unset_as_sdirs_confs);
	tcase_add_test(tc_core, test_phase2_unset_sdirs_confs);
	tcase_add_test(tc_core, test_phase2_unset_confs);
	tcase_add_test(tc_core, test_phase2_unset_sdirs);
	tcase_add_test(tc_core, test_phase2_unset_asfd);

	suite_add_tcase(s, tc_core);

	return s;
}
