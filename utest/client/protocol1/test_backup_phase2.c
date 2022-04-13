#include "../../test.h"
#include "../../builders/build.h"
#include "../../prng.h"
#include "../../../src/alloc.h"
#include "../../../src/asfd.h"
#include "../../../src/async.h"
#include "../../../src/attribs.h"
#include "../../../src/base64.h"
#include "../../../src/client/protocol1/backup_phase2.h"
#include "../../../src/fsops.h"
#include "../../../src/handy.h"
#include "../../../src/hexmap.h"
#include "../../../src/iobuf.h"
#include "../../../src/slist.h"
#include "../../builders/build_asfd_mock.h"
#include "../../builders/build_file.h"

#define BASE	"utest_client_protocol1_backup_phase2"

static struct ioevent_list reads;
static struct ioevent_list writes;

static void tear_down_asfd(struct asfd **asfd)
{
	asfd_free(asfd);
	asfd_mock_teardown(&reads, &writes);
	alloc_check();
}

static void tear_down_async(struct async **as, struct conf ***confs)
{
	async_free(as);
	confs_free(confs);
	alloc_check();
}

START_TEST(test_phase2_no_asfd)
{
	fail_unless(backup_phase2_client_protocol1(
		NULL, // asfd
		NULL, // confs
		0 // resume
	)==-1);
	alloc_check();
}
END_TEST

static void setup_phase2_read_write_error(struct asfd *asfd)
{
	int r=0; int w=0;
	asfd_assert_write(asfd, &w, 0, CMD_GEN, "backupphase2");
	asfd_mock_read(asfd, &r, 0, CMD_GEN, "ok");
	asfd_mock_read(asfd, &r, -1, CMD_GEN, "blah");
}

START_TEST(test_phase2_read_write_error)
{
	struct asfd *asfd;
	asfd=asfd_mock_setup(&reads, &writes);
	setup_phase2_read_write_error(asfd);
	fail_unless(backup_phase2_client_protocol1(
		asfd,
		NULL, // confs
		0 // resume
	)==-1);
	tear_down_asfd(&asfd);
}
END_TEST

static void setup_phase2_empty_backup_ok(struct asfd *asfd)
{
	int r=0; int w=0;
	asfd_assert_write(asfd, &w, 0, CMD_GEN, "backupphase2");
	asfd_mock_read(asfd, &r, 0, CMD_GEN, "ok");
	asfd_mock_read(asfd, &r, 0, CMD_GEN, "backupphase2end");
	asfd_assert_write(asfd, &w, 0, CMD_GEN, "okbackupphase2end");
}

START_TEST(test_phase2_empty_backup_ok)
{
	struct asfd *asfd;
	asfd=asfd_mock_setup(&reads, &writes);
	setup_phase2_empty_backup_ok(asfd);
	fail_unless(backup_phase2_client_protocol1(
		asfd,
		NULL, // confs
		0 // resume
	)==0);
	tear_down_asfd(&asfd);
}
END_TEST

static void setup_phase2_empty_backup_ok_with_warning(struct asfd *asfd)
{
	int r=0; int w=0;
	asfd_assert_write(asfd, &w, 0, CMD_GEN, "backupphase2");
	asfd_mock_read(asfd, &r, 0, CMD_GEN, "ok");
	asfd_mock_read(asfd, &r, 0, CMD_WARNING, "some warning");
	asfd_mock_read(asfd, &r, 0, CMD_GEN, "backupphase2end");
	asfd_assert_write(asfd, &w, 0, CMD_GEN, "okbackupphase2end");
}

START_TEST(test_phase2_empty_backup_ok_with_warning)
{
	struct asfd *asfd;
	asfd=asfd_mock_setup(&reads, &writes);
	setup_phase2_empty_backup_ok_with_warning(asfd);
	fail_unless(backup_phase2_client_protocol1(
		asfd,
		NULL, // confs
		0 // resume
	)==0);
	tear_down_asfd(&asfd);
}
END_TEST

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

static void setup_asfds_with_slist_new_files(struct asfd *asfd,
	struct slist *slist)
{
	int r=0; int w=0;
	struct sbuf *s;

	asfd_assert_write(asfd, &w, 0, CMD_GEN, "backupphase2");
	asfd_mock_read(asfd, &r, 0, CMD_GEN, "ok");

	for(s=slist->head; s; s=s->next)
	{
		if(sbuf_is_filedata(s)
		  || sbuf_is_vssdata(s))
		{
			build_file(s->path.buf, NULL);
			fail_unless(!lstat(s->path.buf, &s->statp));
			s->winattr=0;
			s->compression=0;
			attribs_encode(s);
			asfd_mock_read_iobuf(asfd, &r, 0, &s->attr);
			asfd_mock_read_iobuf(asfd, &r, 0, &s->path);
		}
	}

	asfd_mock_read(asfd, &r, 0, CMD_GEN, "backupphase2end");

	for(s=slist->head; s; s=s->next)
	{
		if(sbuf_is_filedata(s)
		  || sbuf_is_vssdata(s))
		{
			asfd_assert_write_iobuf(asfd, &w, 0, &s->attr);
			asfd_assert_write_iobuf(asfd, &w, 0, &s->path);
			asfd_assert_write(asfd, &w, 0, CMD_END_FILE,
				"0:d41d8cd98f00b204e9800998ecf8427e");
		}
	}
	asfd_assert_write(asfd, &w, 0, CMD_GEN, "okbackupphase2end");
}

static void setup_asfds_with_slist_changed_files(struct asfd *asfd,
	struct slist *slist)
{
	int r=0; int w=0;
	struct sbuf *s;
	char empty_sig[12]={'r', 's', 0x01, '6',
		0, 0, 0, '@', 0, 0, 0, 0x08};
	char *cp;
	long our_lrv=0;
	long lrv201;

	lrv201=version_to_long("2.0.1");
	if((cp=strchr(rs_librsync_version, ' ')))
		our_lrv=version_to_long(cp+1);

	asfd_assert_write(asfd, &w, 0, CMD_GEN, "backupphase2");
	asfd_mock_read(asfd, &r, 0, CMD_GEN, "ok");

	for(s=slist->head; s; s=s->next)
	{
		if(sbuf_is_filedata(s)
		  || sbuf_is_vssdata(s))
		{
			struct iobuf rbuf;
			build_file(s->path.buf, NULL);
			fail_unless(!lstat(s->path.buf, &s->statp));
			s->winattr=0;
			s->compression=0;
			attribs_encode(s);
			if(sbuf_is_encrypted(s))
			{
				asfd_mock_read_iobuf(asfd, &r, 0, &s->attr);
				asfd_mock_read_iobuf(asfd, &r, 0, &s->path);
				continue;
			}
			asfd_mock_read(asfd, &r, 0, CMD_DATAPTH, "somepath");
			asfd_mock_read_iobuf(asfd, &r, 0, &s->attr);
			asfd_mock_read_iobuf(asfd, &r, 0, &s->path);
			iobuf_set(&rbuf, CMD_APPEND,
				empty_sig, sizeof(empty_sig));
			asfd_mock_read_iobuf(asfd, &r, 0, &rbuf);
			asfd_mock_read(asfd, &r, 0, CMD_END_FILE, "endfile");
		}
	}

	asfd_mock_read(asfd, &r, 0, CMD_GEN, "backupphase2end");

	for(s=slist->head; s; s=s->next)
	{
		if(sbuf_is_filedata(s)
		  || sbuf_is_vssdata(s))
		{
			struct iobuf wbuf;
			if(sbuf_is_encrypted(s))
			{
				asfd_assert_write_iobuf(asfd, &w, 0, &s->attr);
				asfd_assert_write_iobuf(asfd, &w, 0, &s->path);
				asfd_assert_write(asfd, &w, 0, CMD_END_FILE,
					"0:d41d8cd98f00b204e9800998ecf8427e");
				continue;
			}
			asfd_assert_write(asfd, &w, 0, CMD_DATAPTH, "somepath");
			asfd_assert_write_iobuf(asfd, &w, 0, &s->attr);
			asfd_assert_write_iobuf(asfd, &w, 0, &s->path);
			if(our_lrv>=lrv201)
			{
				// Brew on macs now gets librsync 2, which
				// gives you the empty delta in one go.
				char empty_delta[5]={'r', 's', 0x02, '6', 0x00};
				iobuf_set(&wbuf, CMD_APPEND,
					empty_delta, sizeof(empty_delta));
			}
			else
			{
				char empty_delta[4]={'r', 's', 0x02, '6'};
				iobuf_set(&wbuf, CMD_APPEND,
					empty_delta, sizeof(empty_delta));
				asfd_assert_write_iobuf(asfd, &w, 0, &wbuf);
				iobuf_set(&wbuf, CMD_APPEND, (char *)"", 1);
			}
			asfd_assert_write_iobuf(asfd, &w, 0, &wbuf);
			asfd_assert_write(asfd, &w, 0, CMD_END_FILE,
				"0:d41d8cd98f00b204e9800998ecf8427e");
		}
	}
	asfd_assert_write(asfd, &w, 0, CMD_GEN, "okbackupphase2end");
}

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
		slist=build_slist_phase1(BASE, slist_entries);
	setup_asfds_callback(asfd, slist);

	fail_unless(backup_phase2_client_protocol1(asfd,
		confs, 0 /* resume */)==expected_ret);

	asfd_free(&asfd);
	asfd_mock_teardown(&reads, &writes);
	slist_free(&slist);
	tear_down_async(&as, &confs);

	fail_unless(!recursive_delete(BASE));
}

START_TEST(test_phase2_with_slist_new_files)
{
	run_test(0, 10, setup_asfds_with_slist_new_files);
}
END_TEST

START_TEST(test_phase2_with_slist_changed_files)
{
	run_test(0, 10, setup_asfds_with_slist_changed_files);
}
END_TEST

Suite *suite_client_protocol1_backup_phase2(void)
{
	Suite *s;
	TCase *tc_core;

	s=suite_create("client_protocol1_backup_phase2");

	tc_core=tcase_create("Core");

	tcase_add_test(tc_core, test_phase2_no_asfd);
	tcase_add_test(tc_core, test_phase2_read_write_error);
	tcase_add_test(tc_core, test_phase2_empty_backup_ok);
	tcase_add_test(tc_core, test_phase2_empty_backup_ok_with_warning);
	tcase_add_test(tc_core, test_phase2_with_slist_new_files);
	tcase_add_test(tc_core, test_phase2_with_slist_changed_files);

	suite_add_tcase(s, tc_core);

	return s;
}
