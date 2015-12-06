#include "../../test.h"
#include "../../../src/alloc.h"
#include "../../../src/asfd.h"
#include "../../../src/async.h"
#include "../../../src/fsops.h"
#include "../../../src/iobuf.h"
#include "../../../src/server/protocol2/backup_phase2.h"
#include "../../../src/server/sdirs.h"
#include "../../builders/build_asfd_mock.h"

#define BASE	"utest_server_protocol2_backup_phase2"

static struct ioevent_list areads;
static struct ioevent_list awrites;
static struct ioevent_list creads;
static struct ioevent_list cwrites;

static void do_sdirs_init(struct sdirs *sdirs)
{
	fail_unless(!sdirs_init(sdirs, PROTO_2,
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
	fail_unless(backup_phase2_server_protocol2(
		NULL, // as
		NULL, // sdirs
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
	fail_unless(backup_phase2_server_protocol2(
		as,
		NULL, // sdirs
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
	fail_unless(backup_phase2_server_protocol2(
		as,
		sdirs,
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
	fail_unless(backup_phase2_server_protocol2(
		as,
		NULL, // sdirs
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
	fail_unless(backup_phase2_server_protocol2(
		as,
		sdirs,
		0, // resume
		confs
	)==-1);
	tear_down(&as, &sdirs, &confs);
}
END_TEST

START_TEST(test_phase2_unset_chfd)
{
	struct asfd *asfd;
	struct async *as;
	struct sdirs *sdirs;
	struct conf **confs;
	setup(&as, &sdirs, &confs);
	asfd=asfd_mock_setup(&areads, &awrites, 10, 10);
	as->asfd_add(as, asfd);

	fail_unless(backup_phase2_server_protocol2(
		as,
		sdirs,
		0, // resume
		confs
	)==-1);
	asfd_free(&asfd);
	asfd_mock_teardown(&areads, &awrites);
	tear_down(&as, &sdirs, &confs);
}
END_TEST

static void setup_asfd(void)
{
//	int r=0;
	int w=0;
	asfd_mock_write(&w, 0, CMD_GEN, "requests_end");
//	asfd_mock_read (&r, 0, CMD_GEN, "requests_end");
}

static int my_async_read_write(struct async *as)
{
	return 0;
}

START_TEST(test_phase2_xxx)
{
	struct asfd *asfd;
	struct asfd *chfd;
	struct async *as;
	struct sdirs *sdirs;
	struct conf **confs;
	setup(&as, &sdirs, &confs);
	asfd=asfd_mock_setup(&areads, &awrites, 10, 10);
	chfd=asfd_mock_setup(&creads, &cwrites, 10, 10);
	as->asfd_add(as, asfd);
	as->asfd_add(as, chfd);
	as->read_write=my_async_read_write;

	setup_asfd();
//	fail_unless(backup_phase2_server_protocol2(
//		as,
//		sdirs,
//		0, // resume
//		confs
//	)==-1);
	asfd_free(&asfd);
	asfd_free(&chfd);
	asfd_mock_teardown(&areads, &awrites);
	asfd_mock_teardown(&creads, &cwrites);
	tear_down(&as, &sdirs, &confs);
}
END_TEST

Suite *suite_server_protocol2_backup_phase2(void)
{
	Suite *s;
	TCase *tc_core;

	s=suite_create("server_protocol2_backup_phase2");

	tc_core=tcase_create("Core");

	tcase_add_test(tc_core, test_phase2_unset_as_sdirs_confs);
	tcase_add_test(tc_core, test_phase2_unset_sdirs_confs);
	tcase_add_test(tc_core, test_phase2_unset_confs);
	tcase_add_test(tc_core, test_phase2_unset_sdirs);
	tcase_add_test(tc_core, test_phase2_unset_asfd);
	tcase_add_test(tc_core, test_phase2_unset_chfd);
//	tcase_add_test(tc_core, test_phase2_xxx);

	suite_add_tcase(s, tc_core);

	return s;
}
