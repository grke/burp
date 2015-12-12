#include "../../test.h"
#include "../../builders/build.h"
#include "../../prng.h"
#include "../../../src/alloc.h"
#include "../../../src/asfd.h"
#include "../../../src/async.h"
#include "../../../src/base64.h"
#include "../../../src/hexmap.h"
#include "../../../src/fsops.h"
#include "../../../src/iobuf.h"
#include "../../../src/server/protocol2/backup_phase2.h"
#include "../../../src/server/sdirs.h"
#include "../../../src/slist.h"
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

static void setup_asfds_empty(struct asfd *asfd, struct asfd *chfd,
	struct slist *slist)
{
	int ar=0, aw=0, cw=0;
	asfd_mock_write(asfd, &aw, 0, CMD_GEN, "requests_end");
	asfd_mock_read (asfd, &ar, 0, CMD_GEN, "sigs_end");
	asfd_mock_write(asfd, &aw, 0, CMD_GEN, "blk_requests_end");
	asfd_mock_read (asfd, &ar, 0, CMD_GEN, "backup_end");

	asfd_mock_write(chfd, &cw, 0, CMD_GEN, "sigs_end");
}

static void setup_asfds_empty_and_messages(struct asfd *asfd, struct asfd *chfd,
	struct slist *slist)
{
	int ar=0, aw=0, cw=0;
	asfd_mock_read (asfd, &ar, 0, CMD_MESSAGE, "a message");
	asfd_mock_write(asfd, &aw, 0, CMD_GEN, "requests_end");
	asfd_mock_read (asfd, &ar, 0, CMD_MESSAGE, "a message");
	asfd_mock_read (asfd, &ar, 0, CMD_GEN, "sigs_end");
	asfd_mock_read (asfd, &ar, 0, CMD_WARNING, "a warning");
	asfd_mock_read (asfd, &ar, 0, CMD_WARNING, "another warning");
	asfd_mock_write(asfd, &aw, 0, CMD_GEN, "blk_requests_end");
	asfd_mock_read (asfd, &ar, 0, CMD_MESSAGE, "a message");
	asfd_mock_read (asfd, &ar, 0, CMD_GEN, "backup_end");

	asfd_mock_write(chfd, &cw, 0, CMD_GEN, "sigs_end");
}

static void setup_asfds_data_too_soon(struct asfd *asfd, struct asfd *chfd,
	struct slist *slist)
{
	int ar=0, aw=0;
	asfd_mock_write(asfd, &aw, 0, CMD_GEN, "requests_end");
	asfd_mock_read (asfd, &ar, 0, CMD_DATA, "some data");
}

static void setup_asfds_write_error(struct asfd *asfd, struct asfd *chfd,
	struct slist *slist)
{
	int aw=0;
	asfd_mock_write(asfd, &aw, -1, CMD_GEN, "requests_end");
}

static void setup_asfds_write_error_chfd(struct asfd *asfd, struct asfd *chfd,
	struct slist *slist)
{
	int ar=0, aw=0, cw=0;
	asfd_mock_write(asfd, &aw, 0, CMD_GEN, "requests_end");
	asfd_mock_read (asfd, &ar, 0, CMD_GEN, "sigs_end");
	asfd_mock_write(asfd, &aw, 0, CMD_GEN, "blk_requests_end");

	asfd_mock_write(chfd, &cw, -1, CMD_GEN, "sigs_end");
}

static void setup_asfds_read_error(struct asfd *asfd, struct asfd *chfd,
	struct slist *slist)
{
	int ar=0, aw=0;
	asfd_mock_write(asfd, &aw,  0, CMD_GEN, "requests_end");
	asfd_mock_read (asfd, &ar, -1, CMD_DATA, "some data");
}

static void setup_asfds_read_error_chfd(struct asfd *asfd, struct asfd *chfd,
	struct slist *slist)
{
	int aw=0, cr=0;
	asfd_mock_write(asfd, &aw,  0, CMD_GEN, "requests_end");
	asfd_mock_read (chfd, &cr, -1, CMD_SIG, "some sig");
}

static void setup_asfds_chfd_bad_cmd(struct asfd *asfd, struct asfd *chfd,
	struct slist *slist)
{
	int aw=0, cr=0;
	asfd_mock_write(asfd, &aw,  0, CMD_GEN, "requests_end");
	asfd_mock_read (chfd, &cr,  0, CMD_MESSAGE, "some message");
}

static void setup_asfds_no_blocks_from_client(struct asfd *asfd,
	struct asfd *chfd, struct slist *slist)
{
	struct sbuf *s;
	int ar=0, aw=0, cw=0;

	if(slist) for(s=slist->head; s; s=s->next)
	{
		if(sbuf_is_filedata(s)
		  && !sbuf_is_encrypted(s)) // Not working for proto2 yet.
			asfd_mock_write(asfd,
				&aw, 0, s->path.cmd, s->path.buf);
	}
	asfd_mock_write(asfd, &aw, 0, CMD_GEN, "requests_end");
	asfd_mock_read_no_op(asfd, &ar, 30);
	asfd_mock_read (asfd, &ar, 0, CMD_GEN, "sigs_end");
	asfd_mock_write(asfd, &aw, 0, CMD_GEN, "blk_requests_end");
	asfd_mock_read (asfd, &ar, 0, CMD_GEN, "backup_end");

	asfd_mock_write(chfd, &cw, 0, CMD_GEN, "sigs_end");
}

static int async_rw_simple(struct async *as)
{
	return as->asfd->read(as->asfd);
}

static int async_rw_both(struct async *as)
{
	int ret=0;
	struct asfd *asfd=as->asfd;
	struct asfd *chfd=asfd->next;
	ret|=asfd->read(asfd);
	ret|=chfd->read(chfd);
	return ret;
}

static void run_test(int expected_ret,
	int manio_entries,
	int async_read_write_callback(struct async *as),
	void setup_asfds_callback(struct asfd *asfd, struct asfd *chfd,
		struct slist *slist))
{
	struct asfd *asfd;
	struct asfd *chfd;
	struct async *as;
	struct sdirs *sdirs;
	struct conf **confs;
	struct slist *slist=NULL;
	setup(&as, &sdirs, &confs);
	asfd=asfd_mock_setup(&areads, &awrites, 50, 50);
	chfd=asfd_mock_setup(&creads, &cwrites, 10, 10);
	chfd->fdtype=ASFD_FD_SERVER_TO_CHAMP_CHOOSER;
	as->asfd_add(as, asfd);
	as->asfd_add(as, chfd);
	as->read_write=async_read_write_callback;

	if(manio_entries)
		slist=build_manifest(sdirs->phase1data,
			PROTO_2, manio_entries, 1 /*phase*/);
	setup_asfds_callback(asfd, chfd, slist);

	fail_unless(backup_phase2_server_protocol2(
		as,
		sdirs,
		0, // resume
		confs
	)==expected_ret);

	if(!expected_ret)
	{
		// FIX THIS: Should check for the presence and correctness of
		// changed and unchanged manios.
	}
	asfd_free(&asfd);
	asfd_free(&chfd);
	asfd_mock_teardown(&areads, &awrites);
	asfd_mock_teardown(&creads, &cwrites);
	slist_free(&slist);
	tear_down(&as, &sdirs, &confs);
}

START_TEST(test_phase2)
{
	prng_init(0);
	base64_init();
	hexmap_init();
	run_test( 0, 0, async_rw_simple, setup_asfds_empty);
	run_test( 0, 0, async_rw_simple, setup_asfds_empty_and_messages);
	run_test(-1, 0, async_rw_simple, setup_asfds_data_too_soon);
	run_test(-1, 0, async_rw_simple, setup_asfds_write_error);
	run_test(-1, 0, async_rw_simple, setup_asfds_write_error_chfd);
	run_test(-1, 0, async_rw_simple, setup_asfds_read_error);
	run_test(-1, 0, async_rw_both,   setup_asfds_read_error_chfd);
	run_test(-1, 0, async_rw_both,   setup_asfds_chfd_bad_cmd);
	run_test(-1, 20, async_rw_simple, setup_asfds_no_blocks_from_client);
}
END_TEST

Suite *suite_server_protocol2_backup_phase2(void)
{
	Suite *s;
	TCase *tc_core;

	s=suite_create("server_protocol2_backup_phase2");

	tc_core=tcase_create("Core");
	tcase_set_timeout(tc_core, 10);

	tcase_add_test(tc_core, test_phase2_unset_as_sdirs_confs);
	tcase_add_test(tc_core, test_phase2_unset_sdirs_confs);
	tcase_add_test(tc_core, test_phase2_unset_confs);
	tcase_add_test(tc_core, test_phase2_unset_sdirs);
	tcase_add_test(tc_core, test_phase2_unset_asfd);
	tcase_add_test(tc_core, test_phase2_unset_chfd);
	tcase_add_test(tc_core, test_phase2);

	suite_add_tcase(s, tc_core);

	return s;
}
