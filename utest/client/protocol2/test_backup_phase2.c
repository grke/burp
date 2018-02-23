#include "../../test.h"
#include "../../builders/build.h"
#include "../../builders/build_file.h"
#include "../../prng.h"
#include "../../../src/alloc.h"
#include "../../../src/asfd.h"
#include "../../../src/async.h"
#include "../../../src/attribs.h"
#include "../../../src/base64.h"
#include "../../../src/client/protocol2/backup_phase2.h"
#include "../../../src/server/protocol2/backup_phase2.h"
#include "../../../src/fsops.h"
#include "../../../src/hexmap.h"
#include "../../../src/protocol2/blk.h"
#include "../../../src/iobuf.h"
#include "../../../src/slist.h"
#include "../../builders/build_asfd_mock.h"

#define BASE	"utest_client_protocol2_backup_phase2"

static struct ioevent_list reads;
static struct ioevent_list writes;

static void tear_down(struct async **as)
{
	async_asfd_free_all(as);
	asfd_mock_teardown(&reads, &writes);
	alloc_check();
}

static void tear_down_async(struct async **as, struct conf ***confs)
{
	async_free(as);
	confs_free(confs);
//printf("%d %d\n", alloc_count, free_count);
	alloc_check();
}

static struct async *setup_async(void)
{
        struct async *as;
        fail_unless((as=async_alloc())!=NULL);
        as->init(as, 0 /* estimate */);
        return as;
}

static struct conf **setup_conf(void)
{
	struct conf **confs=NULL;
	fail_unless((confs=confs_alloc())!=NULL);
	fail_unless(!confs_init(confs));
	set_int(confs[OPT_COMPRESSION], 0);
	return confs;
}

static int async_rw_simple(struct async *as)
{
	return as->asfd->read(as->asfd);
}

static int async_write_simple(struct async *as)
{
	return 0;
}

START_TEST(test_phase2_no_asfd)
{
	fail_unless(backup_phase2_client_protocol2(
		NULL, // asfd
		NULL, // confs
		0 // resume
	)==-1);
	alloc_check();
}
END_TEST

static void setup_phase2_ok(struct asfd *asfd)
{
	int r=0; int w=0;
	asfd_assert_write(asfd, &w, 0, CMD_GEN, "backupphase2");
	asfd_mock_read(asfd, &r, 0, CMD_GEN, "ok");
}

static int mock_async_read_write_error(struct async *as)
{
	return -1;
}

static int mock_async_read(struct async *as)
{
	return as->asfd->read(as->asfd);
}

static struct async *async_mock_setup(void)
{
	struct async *as;
	fail_unless((as=async_alloc())!=NULL);
	as->init(as, 0 /* estimate */);
	return as;
}

static void setup_phase2_server_bad_initial_response(struct asfd *asfd)
{
	int r=0; int w=0;
	asfd_assert_write(asfd, &w, 0, CMD_GEN, "backupphase2");
	asfd_mock_read(asfd, &r, 0, CMD_GEN, "notok");
}

static void setup_phase2_ok_then_cmd_error(struct asfd *asfd)
{
	int r=0; int w=0;
	asfd_assert_write(asfd, &w, 0, CMD_GEN, "backupphase2");
	asfd_mock_read(asfd, &r, 0, CMD_GEN, "ok");
	asfd_mock_read(asfd, &r, 0, CMD_ERROR, "some error");
}

static void setup_phase2_ok_file_request_missing_file(struct asfd *asfd)
{
	char buf[32];
	int r=0; int w=0;
	asfd_assert_write(asfd, &w, 0, CMD_GEN, "backupphase2");
	asfd_mock_read(asfd, &r, 0, CMD_GEN, "ok");
	asfd_mock_read(asfd, &r, 0, CMD_FILE, "some file");
	asfd_assert_write(asfd, &w, 0, CMD_WARNING,
		"f:0009:some file has vanished\n");
	base64_from_uint64(1, buf);
	asfd_assert_write(asfd, &w, 0, CMD_INTERRUPT, buf);
	asfd_mock_read(asfd, &r, 0, CMD_ERROR, "some error");
}

static void run_error_test(int expected_ret,
	int async_func(struct async *as),
	void asfd_setup_callback(struct asfd *asfd))
{
	struct asfd *asfd;
	struct async *as;
	asfd=asfd_mock_setup(&reads, &writes);
	as=async_mock_setup();
	as->asfd_add(as, asfd);
	asfd->as=as;
	asfd_setup_callback(asfd);
	as->read_write=async_func;
	fail_unless(backup_phase2_client_protocol2(
		asfd,
		NULL, // confs
		0 // resume
	)==expected_ret);
	tear_down(&as);
}

START_TEST(test_phase2_as_read_write_error)
{
	run_error_test(-1, mock_async_read_write_error, setup_phase2_ok);
}
END_TEST

START_TEST(test_phase2_server_bad_initial_response)
{
	run_error_test(-1, mock_async_read,
		setup_phase2_server_bad_initial_response);
}
END_TEST

START_TEST(test_phase2_ok_then_cmd_error)
{
	run_error_test(-1, mock_async_read, setup_phase2_ok_then_cmd_error);
}
END_TEST

START_TEST(test_phase2_ok_file_request_missing_file)
{
	// FIX THIS - a missing file should not cause a fatal error!
	run_error_test(-1,
		mock_async_read, setup_phase2_ok_file_request_missing_file);
}
END_TEST

static void run_test(int expected_ret,
	int slist_entries,
	void setup_asfds_callback(struct asfd *asfd, struct slist *slist))
{
	struct asfd *asfd;
	struct async *as;
	struct conf **confs;
	struct slist *slist=NULL;

	fail_unless(!recursive_delete(BASE));

	prng_init(0);
	base64_init();
	hexmap_init();

	as=setup_async();
	confs=setup_conf();
	asfd=asfd_mock_setup(&reads, &writes);
	as->asfd_add(as, asfd);
	asfd->as=as;
	as->read_write=async_rw_simple;
	as->write=async_write_simple;

	if(slist_entries)
		slist=build_slist_phase1(BASE, PROTO_2, slist_entries);
	setup_asfds_callback(asfd, slist);

	fail_unless(backup_phase2_client_protocol2(asfd,
		confs, 0 /* resume */)==expected_ret);

	asfd_free(&asfd);
	asfd_mock_teardown(&reads, &writes);
	slist_free(&slist);
	tear_down_async(&as, &confs);

	fail_unless(!recursive_delete(BASE));
}

static void ask_for_blk(int blk_index, struct asfd *asfd, int *r, int *w)
{
	char req[32]="";
	struct iobuf iobuf;
	base64_from_uint64(blk_index, req);
	iobuf_from_str(&iobuf, CMD_DATA_REQ, req);
	asfd_mock_read_iobuf(asfd, r, 0, &iobuf);
	asfd_assert_write(asfd, w, 0, CMD_DATA, "1");
}

static void build_file_and_assert_writes(struct sbuf *s,
	struct asfd *asfd, int *w)
{
	struct blk blk;
	struct iobuf iobuf;
	build_file(s->path.buf, "1");
	fail_unless(!lstat(s->path.buf, &s->statp));
	s->winattr=0;
	s->compression=0;
	s->encryption=ENCRYPTION_NONE;
	attribs_encode(s);
	s->attr.cmd=CMD_ATTRIBS_SIGS;
	asfd_assert_write_iobuf(asfd, w, 0, &s->attr);
	blk.fingerprint=0x0000000000000031;
	md5str_to_bytes("c4ca4238a0b923820dcc509a6f75849b", blk.md5sum);
	blk_to_iobuf_sig(&blk, &iobuf);
	asfd_assert_write_iobuf(asfd, w, 0, &iobuf);
}

static void setup_asfds_happy_path(struct asfd *asfd, struct slist *slist)
{
	int r=0, w=0;
	int file_no=1;
	struct sbuf *s;
	char req[32]="";
	struct iobuf iobuf;

	asfd_assert_write(asfd, &w, 0, CMD_GEN, "backupphase2");
	asfd_mock_read(asfd, &r, 0, CMD_GEN, "ok");

	for(s=slist->head; s; s=s->next)
	{
		if(sbuf_is_filedata(s)
		  || sbuf_is_vssdata(s))
		{
			asfd_mock_read_iobuf(asfd, &r, 0, &s->path);
			s->protocol2->index=file_no++;

			build_file_and_assert_writes(s, asfd, &w);
		}
	}

	asfd_mock_read(asfd, &r, 0, CMD_WARNING, "a warning");
	asfd_mock_read_no_op(asfd, &r, 10);
	asfd_mock_read(asfd, &r, 0, CMD_GEN, "requests_end");
	asfd_assert_write(asfd, &w, 0, CMD_GEN, "sigs_end");

	// Wrap up to block 2.
	base64_from_uint64(2, req);
	iobuf_from_str(&iobuf, CMD_WRAP_UP, req);
	asfd_mock_read_iobuf(asfd, &r, 0, &iobuf);

	ask_for_blk(3, asfd, &r, &w);

	asfd_mock_read(asfd, &r, 0, CMD_GEN, "blk_requests_end");
	asfd_mock_read(asfd, &r, 0, CMD_GEN, "backup_end");
	asfd_assert_write(asfd, &w, 0, CMD_GEN, "backup_end");
}

static void setup_asfds_happy_path_missing_file_index(struct asfd *asfd,
	struct slist *slist, uint64_t index)
{
	int r=0, w=0;
	int file_no=1;
	struct sbuf *s;

	asfd_assert_write(asfd, &w, 0, CMD_GEN, "backupphase2");
	asfd_mock_read(asfd, &r, 0, CMD_GEN, "ok");

	for(s=slist->head; s; s=s->next)
	{
		if(sbuf_is_filedata(s)
		  || sbuf_is_vssdata(s))
		{
			if(sbuf_is_encrypted(s)) continue;
			asfd_mock_read_iobuf(asfd, &r, 0, &s->path);
			asfd_mock_read_no_op(asfd, &r, 2);
			s->protocol2->index=file_no++;
			if(s->protocol2->index==index)
			{
				char buf[32]="";
				char warn[256]="";
				snprintf(warn, sizeof(warn),
					"%s has vanished\n",
					iobuf_to_printable(&s->path));
				asfd_assert_write(asfd, &w, 0, CMD_WARNING,
					warn);
				base64_from_uint64(s->protocol2->index, buf);
				asfd_assert_write(asfd, &w, 0, CMD_INTERRUPT,
					buf);
			}
			else
			{
				build_file_and_assert_writes(s, asfd, &w);
			}
		}
	}

	asfd_mock_read_no_op(asfd, &r, 10);
	asfd_mock_read(asfd, &r, 0, CMD_GEN, "requests_end");
	asfd_assert_write(asfd, &w, 0, CMD_GEN, "sigs_end");

	ask_for_blk(3, asfd, &r, &w);

	asfd_mock_read(asfd, &r, 0, CMD_GEN, "blk_requests_end");
	asfd_mock_read(asfd, &r, 0, CMD_GEN, "backup_end");
	asfd_assert_write(asfd, &w, 0, CMD_GEN, "backup_end");
}

static void setup_asfds_happy_path_missing_file_1(struct asfd *asfd,
	struct slist *slist)
{
	setup_asfds_happy_path_missing_file_index(asfd, slist, 1);
}

static void setup_asfds_happy_path_missing_file_2(struct asfd *asfd,
	struct slist *slist)
{
	setup_asfds_happy_path_missing_file_index(asfd, slist, 2);
}

START_TEST(test_phase2_happy_path)
{
	run_test(0, 10, setup_asfds_happy_path);
}
END_TEST

START_TEST(test_phase2_happy_path_missing_file_1)
{
	run_test(0, 10, setup_asfds_happy_path_missing_file_1);
}
END_TEST

START_TEST(test_phase2_happy_path_missing_file_2)
{
	run_test(0, 10, setup_asfds_happy_path_missing_file_2);
}
END_TEST

Suite *suite_client_protocol2_backup_phase2(void)
{
	Suite *s;
	TCase *tc_core;

	s=suite_create("client_protocol2_backup_phase2");

	tc_core=tcase_create("Core");
	tcase_set_timeout(tc_core, 60);

	tcase_add_test(tc_core, test_phase2_no_asfd);
	tcase_add_test(tc_core, test_phase2_as_read_write_error);
	tcase_add_test(tc_core, test_phase2_ok_then_cmd_error);
	tcase_add_test(tc_core, test_phase2_server_bad_initial_response);
	tcase_add_test(tc_core, test_phase2_ok_file_request_missing_file);
	tcase_add_test(tc_core, test_phase2_happy_path);
	tcase_add_test(tc_core, test_phase2_happy_path_missing_file_1);
	tcase_add_test(tc_core, test_phase2_happy_path_missing_file_2);

	suite_add_tcase(s, tc_core);

	return s;
}
