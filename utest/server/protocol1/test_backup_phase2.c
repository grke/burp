#include "../../test.h"
#include "../../builders/build.h"
#include "../../prng.h"
#include "../../../src/alloc.h"
#include "../../../src/asfd.h"
#include "../../../src/async.h"
#include "../../../src/attribs.h"
#include "../../../src/base64.h"
#include "../../../src/bu.h"
#include "../../../src/hexmap.h"
#include "../../../src/fsops.h"
#include "../../../src/iobuf.h"
#include "../../../src/server/protocol1/backup_phase2.h"
#include "../../../src/server/sdirs.h"
#include "../../../src/slist.h"
#include "../../builders/build_asfd_mock.h"

#define BASE	"utest_server_protocol1_backup_phase2"

static struct ioevent_list reads;
static struct ioevent_list writes;

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

static int async_rw_simple(struct async *as)
{
	return as->asfd->read(as->asfd);
}

static struct sd sd1[] = {
	{ "0000001 1970-01-01 00:00:00", 1, 1, BU_WORKING },
};

static void setup_asfds_happy_path_no_files(struct asfd *asfd,
	struct slist *slist)
{
	int r=0, w=0;
	asfd_assert_write(asfd, &w, 0, CMD_GEN, "backupphase2end");
	asfd_mock_read(asfd, &r, 0, CMD_GEN, "okbackupphase2end");
}

static void setup_writes_from_slist(struct asfd *asfd,
	int *w, struct slist *slist)
{
	struct sbuf *s;
	for(s=slist->head; s; s=s->next)
	{
		if(!sbuf_is_filedata(s))
			continue;
		asfd_assert_write_iobuf(asfd, w, 0, &s->attr);
		asfd_assert_write_iobuf(asfd, w, 0, &s->path);
	}
}

static void setup_asfds_happy_path_nothing_from_client(struct asfd *asfd,
	struct slist *slist)
{
	int r=0, w=0;
	setup_writes_from_slist(asfd, &w, slist);
	asfd_assert_write(asfd, &w, 0, CMD_GEN, "backupphase2end");
	asfd_mock_read_no_op(asfd, &r, 20);
	asfd_mock_read(asfd, &r, 0, CMD_GEN, "okbackupphase2end");
}

static void setup_asfds_happy_path_interrupts_from_client(struct asfd *asfd,
	struct slist *slist)
{
	int r=0, w=0;
	struct sbuf *s;
	setup_writes_from_slist(asfd, &w, slist);
	asfd_assert_write(asfd, &w, 0, CMD_GEN, "backupphase2end");
	asfd_mock_read_no_op(asfd, &r, 200);
	for(s=slist->head; s; s=s->next)
	{
		if(!sbuf_is_filedata(s))
			continue;
		asfd_mock_read(asfd, &r, 0, CMD_INTERRUPT, s->path.buf);
	}
	asfd_mock_read(asfd, &r, 0, CMD_GEN, "okbackupphase2end");
}

static void setup_asfds_happy_path_new_files(struct asfd *asfd,
	struct slist *slist)
{
	int r=0, w=0;
	struct sbuf *s;
	setup_writes_from_slist(asfd, &w, slist);
	asfd_assert_write(asfd, &w, 0, CMD_GEN, "backupphase2end");
	asfd_mock_read_no_op(asfd, &r, 200);
	for(s=slist->head; s; s=s->next)
	{
		if(!sbuf_is_filedata(s))
			continue;
		asfd_mock_read_iobuf(asfd, &r, 0, &s->attr);
		asfd_mock_read_iobuf(asfd, &r, 0, &s->path);
		asfd_mock_read(asfd, &r, 0, CMD_APPEND, "some data");
		asfd_mock_read(asfd, &r, 0, CMD_END_FILE,
			"0:d41d8cd98f00b204e9800998ecf8427e");

	}
	asfd_mock_read(asfd, &r, 0, CMD_GEN, "okbackupphase2end");
}

static void run_test(int expected_ret,
        int manio_entries,
        void setup_asfds_callback(struct asfd *asfd, struct slist *slist))
{
	struct asfd *asfd;
	struct async *as;
	struct sdirs *sdirs;
	struct conf **confs;
	struct slist *slist=NULL;
	prng_init(0);
	base64_init();
	hexmap_init();
	setup(&as, &sdirs, &confs);
	asfd=asfd_mock_setup(&reads, &writes);
	as->asfd_add(as, asfd);
	as->read_write=async_rw_simple;
	asfd->as=as;

	build_storage_dirs(sdirs, sd1, ARR_LEN(sd1));
	fail_unless(!sdirs_get_real_working_from_symlink(sdirs));
	if(manio_entries)
	{
		slist=build_manifest(sdirs->phase1data,
				PROTO_2, manio_entries, 1 /*phase*/);
	}
	setup_asfds_callback(asfd, slist);

	fail_unless(backup_phase2_server_protocol1(
		as,
		sdirs,
		NULL, // incexc
		0, // resume
		confs
	)==expected_ret);

	if(!expected_ret)
	{
		// FIX THIS: Should check for the presence and correctness of
		// changed and unchanged manios.
	}
	asfd_free(&asfd);
	asfd_mock_teardown(&reads, &writes);
	slist_free(&slist);
	tear_down(&as, &sdirs, &confs);
}

START_TEST(test_phase2_happy_path_no_files)
{
	run_test(0, 0, setup_asfds_happy_path_no_files);
}
END_TEST

START_TEST(test_phase2_happy_path_nothing_from_client)
{
	run_test(0, 10, setup_asfds_happy_path_nothing_from_client);
}
END_TEST

START_TEST(test_phase2_happy_path_interrupts_from_client)
{
	run_test(0, 100, setup_asfds_happy_path_interrupts_from_client);
}
END_TEST

START_TEST(test_phase2_happy_path_new_files)
{
	run_test(0, 10, setup_asfds_happy_path_new_files);
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

	tcase_add_test(tc_core, test_phase2_happy_path_no_files);
	tcase_add_test(tc_core, test_phase2_happy_path_nothing_from_client);
	tcase_add_test(tc_core, test_phase2_happy_path_interrupts_from_client);
	tcase_add_test(tc_core, test_phase2_happy_path_new_files);

	suite_add_tcase(s, tc_core);

	return s;
}
