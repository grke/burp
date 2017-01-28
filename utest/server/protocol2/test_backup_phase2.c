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
#include "../../../src/protocol2/blk.h"
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
	fail_unless(do_backup_phase2_server_protocol2(
		NULL, // as
		NULL, // chfd
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
	fail_unless(do_backup_phase2_server_protocol2(
		as,
		NULL, // chfd
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
	fail_unless(do_backup_phase2_server_protocol2(
		as,
		NULL, // chfd
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
	fail_unless(do_backup_phase2_server_protocol2(
		as,
		NULL, // chfd
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
	fail_unless(do_backup_phase2_server_protocol2(
		as,
		NULL, // chfd
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
	asfd=asfd_mock_setup(&areads, &awrites);
	as->asfd_add(as, asfd);

	fail_unless(do_backup_phase2_server_protocol2(
		as,
		NULL, // chfd
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
	asfd_assert_write(asfd, &aw, 0, CMD_GEN, "requests_end");
	asfd_mock_read(asfd, &ar, 0, CMD_GEN, "sigs_end");
	asfd_assert_write(asfd, &aw, 0, CMD_GEN, "blk_requests_end");
	asfd_mock_read(asfd, &ar, 0, CMD_GEN, "backup_end");

	asfd_assert_write(chfd, &cw, 0, CMD_GEN, "sigs_end");
}

static void setup_asfds_empty_and_messages(struct asfd *asfd, struct asfd *chfd,
	struct slist *slist)
{
	int ar=0, aw=0, cw=0;
	asfd_mock_read(asfd, &ar, 0, CMD_MESSAGE, "a message");
	asfd_assert_write(asfd, &aw, 0, CMD_GEN, "requests_end");
	asfd_mock_read(asfd, &ar, 0, CMD_MESSAGE, "a message");
	asfd_mock_read(asfd, &ar, 0, CMD_GEN, "sigs_end");
	asfd_mock_read(asfd, &ar, 0, CMD_WARNING, "a warning");
	asfd_mock_read(asfd, &ar, 0, CMD_WARNING, "another warning");
	asfd_assert_write(asfd, &aw, 0, CMD_GEN, "blk_requests_end");
	asfd_mock_read(asfd, &ar, 0, CMD_MESSAGE, "a message");
	asfd_mock_read(asfd, &ar, 0, CMD_GEN, "backup_end");

	asfd_assert_write(chfd, &cw, 0, CMD_GEN, "sigs_end");
}

static void setup_asfds_data_too_soon(struct asfd *asfd, struct asfd *chfd,
	struct slist *slist)
{
	int ar=0, aw=0;
	asfd_assert_write(asfd, &aw, 0, CMD_GEN, "requests_end");
	asfd_mock_read(asfd, &ar, 0, CMD_DATA, "some data");
}

static void setup_asfds_write_error(struct asfd *asfd, struct asfd *chfd,
	struct slist *slist)
{
	int aw=0;
	asfd_assert_write(asfd, &aw, -1, CMD_GEN, "requests_end");
}

static void setup_asfds_write_error_chfd(struct asfd *asfd, struct asfd *chfd,
	struct slist *slist)
{
	int ar=0, aw=0, cw=0;
	asfd_assert_write(asfd, &aw, 0, CMD_GEN, "requests_end");
	asfd_mock_read(asfd, &ar, 0, CMD_GEN, "sigs_end");
	asfd_assert_write(asfd, &aw, 0, CMD_GEN, "blk_requests_end");

	asfd_assert_write(chfd, &cw, -1, CMD_GEN, "sigs_end");
}

static void setup_asfds_read_error(struct asfd *asfd, struct asfd *chfd,
	struct slist *slist)
{
	int ar=0, aw=0;
	asfd_assert_write(asfd, &aw,  0, CMD_GEN, "requests_end");
	asfd_mock_read(asfd, &ar, -1, CMD_DATA, "some data");
}

static void setup_asfds_read_error_chfd(struct asfd *asfd, struct asfd *chfd,
	struct slist *slist)
{
	int ar=0, aw=0, cr=0;
	asfd_assert_write(asfd, &aw,  0, CMD_GEN, "requests_end");
	asfd_mock_read_no_op(asfd, &ar, 1);
	asfd_mock_read(chfd, &cr, -1, CMD_SIG, "some sig");
}

static void setup_asfds_chfd_bad_cmd(struct asfd *asfd, struct asfd *chfd,
	struct slist *slist)
{
	int ar=0, aw=0, cr=0;
	asfd_assert_write(asfd, &aw,  0, CMD_GEN, "requests_end");
	asfd_mock_read_no_op(asfd, &ar, 1);
	asfd_mock_read(chfd, &cr,  0, CMD_MESSAGE, "some message");
}

static void setup_writes_from_slist(struct asfd *asfd,
	int *aw, struct slist *slist)
{
	struct sbuf *s;
	if(!slist) return;
	for(s=slist->head; s; s=s->next)
	{
		if(sbuf_is_filedata(s)
		  && !sbuf_is_encrypted(s)) // Not working for proto2 yet.
		{
			asfd_assert_write(asfd,
				aw, 0, s->path.cmd, s->path.buf);
		}
	}
}

static void setup_asfds_no_sigs_from_client(struct asfd *asfd,
	struct asfd *chfd, struct slist *slist)
{
	int ar=0, aw=0, cw=0;

	setup_writes_from_slist(asfd, &aw, slist);
	asfd_assert_write(asfd, &aw, 0, CMD_GEN, "requests_end");
	asfd_mock_read_no_op(asfd, &ar, 60);
	asfd_mock_read(asfd, &ar, 0, CMD_GEN, "sigs_end");
	asfd_assert_write(asfd, &aw, 0, CMD_GEN, "blk_requests_end");
	asfd_mock_read(asfd, &ar, 0, CMD_GEN, "backup_end");

	asfd_assert_write(chfd, &cw, 0, CMD_GEN, "sigs_end");
}

static void setup_reads_from_slist(struct asfd *asfd,
	int *ar, struct slist *slist, int number_of_blks, uint64_t interrupt)
{
	int file_no=1;
	struct sbuf *s;
	struct blk blk;
	struct iobuf iobuf;
	if(!slist) return;
	for(s=slist->head; s; s=s->next)
	{
		if(sbuf_is_filedata(s)
		  && !sbuf_is_encrypted(s)) // Not working for proto2 yet.
		{
			int b;
			s->protocol2->index=file_no++;
			if(interrupt==s->protocol2->index)
			{
				char buf[32]="";
				asfd_mock_read(asfd,
					ar, 0, CMD_WARNING, "path vanished\n");
				base64_from_uint64(interrupt, buf);
				asfd_mock_read(asfd, ar, 0, CMD_INTERRUPT,
					buf);
				continue;
			}
			iobuf_free_content(&s->attr);
			attribs_encode(s);
			asfd_mock_read(asfd,
				ar, 0, CMD_ATTRIBS_SIGS, s->attr.buf);
			blk.fingerprint=file_no;
			memset(&blk.md5sum, file_no, MD5_DIGEST_LENGTH);
			blk_to_iobuf_sig(&blk, &iobuf);
			for(b=0; b<number_of_blks; b++)
				asfd_mock_read_iobuf(asfd, ar, 0, &iobuf);
		}
	}
}

static void setup_chfd_writes_from_slist(struct asfd *chfd,
	int *cw, struct slist *slist, int number_of_blks, uint64_t interrupt)
{
	struct sbuf *s;
	struct blk blk;
	struct iobuf iobuf;
	uint64_t file_no=1;
	if(!slist) return;
	for(s=slist->head; s; s=s->next)
	{
		if(sbuf_is_filedata(s)
		  && !sbuf_is_encrypted(s)) // Not working for proto2 yet.
		{
			int b;
			if(interrupt==file_no++)
				continue;
			blk.fingerprint=file_no;
			memset(&blk.md5sum, file_no, MD5_DIGEST_LENGTH);
			blk_to_iobuf_sig(&blk, &iobuf);
			for(b=0; b<number_of_blks; b++)
				asfd_assert_write_iobuf(chfd, cw, 0, &iobuf);
		}
	}
}

static void setup_chfd_reads_from_slist_blks_got(struct asfd *chfd,
	int *cr, struct slist *slist, int number_of_blks, uint64_t interrupt)
{
	uint64_t file_no=1;
	int blk_index=1;
	struct blk blk;
	struct iobuf iobuf;
	struct sbuf *s;
	if(!slist) return;
	for(s=slist->head; s; s=s->next)
	{
		if(sbuf_is_filedata(s)
		  && !sbuf_is_encrypted(s)) // Not working for proto2 yet.
		{
			int b;
			if(interrupt==file_no++)
				continue;
			for(b=0; b<number_of_blks; b++)
			{
				blk.index=blk_index++;
				blk.savepath=0;
				blk_to_iobuf_index_and_savepath(&blk, &iobuf);
				asfd_mock_read_iobuf(chfd, cr, 0, &iobuf);
			}
		}
	}
}

static void setup_chfd_reads_from_slist_blks_not_got(struct asfd *chfd,
	int *cr, struct slist *slist, int number_of_blks, uint64_t interrupt)
{
	int blk_index=1;
	uint64_t file_no=1;
	struct blk blk;
	struct iobuf iobuf;
	struct sbuf *s;
	if(!slist) return;
	for(s=slist->head; s; s=s->next)
	{
		if(sbuf_is_filedata(s)
		  && !sbuf_is_encrypted(s)) // Not working for proto2 yet.
		{
			int b;
			if(interrupt==file_no++)
				continue;
			for(b=0; b<number_of_blks; b++)
			{
				blk.index=blk_index++;
				blk_to_iobuf_wrap_up(&blk, &iobuf);
				asfd_mock_read_iobuf(chfd, cr, 0, &iobuf);
			}
		}
	}
}

static void setup_writes_from_slist_blk_requests(struct asfd *asfd,
	int *aw, struct slist *slist, int number_of_blks, uint64_t interrupt)
{
	struct sbuf *s;
	struct iobuf iobuf;
	char req[32]="";
	int blk_index=1;
	uint64_t file_no=1;
	if(!slist) return;
	for(s=slist->head; s; s=s->next)
	{
		if(sbuf_is_filedata(s)
		  && !sbuf_is_encrypted(s)) // Not working for proto2 yet.
		{
			int b;
			if(interrupt==file_no++)
				continue;

                        base64_from_uint64(blk_index, req);
                        iobuf_from_str(&iobuf, CMD_DATA_REQ, req);
                        asfd_assert_write_iobuf(asfd, aw, 0, &iobuf);
                        for(b=0; b<number_of_blks; b++)
                                blk_index++;
		}
	}
}

static void setup_reads_from_slist_blks(struct asfd *asfd,
	int *ar, struct slist *slist, int number_of_blks, uint64_t interrupt)
{
	struct sbuf *s;
	struct blk blk;
	struct iobuf iobuf;
	uint64_t file_no=1;
	if(!slist) return;
	for(s=slist->head; s; s=s->next)
	{
		if(sbuf_is_filedata(s)
		  && !sbuf_is_encrypted(s)) // Not working for proto2 yet.
		{
			if(interrupt==file_no++)
				continue;
			blk_to_iobuf_sig(&blk, &iobuf);
			iobuf_from_str(&iobuf, CMD_DATA, (char *)"some data");
			asfd_mock_read_iobuf(asfd, ar, 0, &iobuf);
		}
	}
}

static void setup_asfds_happy_path_one_blk_per_file_full_dedup(
	struct asfd *asfd, struct asfd *chfd, struct slist *slist)
{
	int ar=0, aw=0, cr=0, cw=0;

	setup_writes_from_slist(asfd, &aw, slist);
	asfd_assert_write(asfd, &aw, 0, CMD_GEN, "requests_end");
	asfd_mock_read_no_op(asfd, &ar, 30);
	setup_reads_from_slist(asfd, &ar, slist, 1, 0);
	asfd_mock_read(asfd, &ar, 0, CMD_GEN, "sigs_end");

	asfd_assert_write(asfd, &aw, 0, CMD_GEN, "blk_requests_end");
	asfd_mock_read_no_op(asfd, &ar, 60);
	asfd_mock_read(asfd, &ar, 0, CMD_GEN, "backup_end");

	setup_chfd_writes_from_slist(chfd, &cw, slist, 1, 0);
	asfd_mock_read_no_op(chfd, &cr, 60);
	setup_chfd_reads_from_slist_blks_got(chfd, &cr, slist, 1, 0);
	asfd_mock_read_no_op(chfd, &cr, 60);
	asfd_assert_write(chfd, &cw, 0, CMD_GEN, "sigs_end");
}

static void setup_asfds_happy_path_one_blk_per_file_full_dedup_big(
	struct asfd *asfd,
	struct asfd *chfd, struct slist *slist)
{
	int ar=0, aw=0, cr=0, cw=0;

	setup_writes_from_slist(asfd, &aw, slist);
	asfd_assert_write(asfd, &aw, 0, CMD_GEN, "requests_end");
	asfd_mock_read_no_op(asfd, &ar, 12800);
	setup_reads_from_slist(asfd, &ar, slist, 1, 0);
	asfd_mock_read(asfd, &ar, 0, CMD_GEN, "sigs_end");

	asfd_assert_write(asfd, &aw, 0, CMD_WRAP_UP, "BOJ");
	asfd_assert_write(asfd, &aw, 0, CMD_GEN, "blk_requests_end");
	asfd_mock_read_no_op(asfd, &ar, 25600);
	asfd_mock_read(asfd, &ar, 0, CMD_GEN, "backup_end");

	setup_chfd_writes_from_slist(chfd, &cw, slist, 1, 0);
	asfd_mock_read_no_op(chfd, &cr, 25600);
	setup_chfd_reads_from_slist_blks_got(chfd, &cr, slist, 1, 0);
	asfd_mock_read_no_op(chfd, &cr, 25600);
	asfd_assert_write(chfd, &cw, 0, CMD_GEN, "sigs_end");
	asfd_assert_write(chfd, &cw, 0, CMD_MANIFEST, "utest_server_protocol2_backup_phase2/a_group/clients/utestclient/working/changed/00000000");
}

static void setup_asfds_happy_path_three_blks_per_file_full_dedup(
	struct asfd *asfd, struct asfd *chfd, struct slist *slist)
{
	int ar=0, aw=0, cr=0, cw=0;

	setup_writes_from_slist(asfd, &aw, slist);
	asfd_assert_write(asfd, &aw, 0, CMD_GEN, "requests_end");
	asfd_mock_read_no_op(asfd, &ar, 200);
	setup_reads_from_slist(asfd, &ar, slist, 3, 0);
	asfd_mock_read(asfd, &ar, 0, CMD_GEN, "sigs_end");

	asfd_assert_write(asfd, &aw, 0, CMD_GEN, "blk_requests_end");
	asfd_mock_read_no_op(asfd, &ar, 1000);
	asfd_mock_read(asfd, &ar, 0, CMD_GEN, "backup_end");

	setup_chfd_writes_from_slist(chfd, &cw, slist, 3, 0);
	asfd_mock_read_no_op(chfd, &cr, 1000);
	setup_chfd_reads_from_slist_blks_got(chfd, &cr, slist, 3, 0);
	asfd_mock_read_no_op(chfd, &cr, 1000);
	asfd_assert_write(chfd, &cw, 0, CMD_GEN, "sigs_end");
}

static void setup_asfds_happy_path_three_blks_per_file_full_dedup_big(
	struct asfd *asfd,
	struct asfd *chfd, struct slist *slist)
{
	int ar=0, aw=0, cr=0, cw=0;

	setup_writes_from_slist(asfd, &aw, slist);
	asfd_assert_write(asfd, &aw, 0, CMD_GEN, "requests_end");
	asfd_mock_read_no_op(asfd, &ar, 12800);
	setup_reads_from_slist(asfd, &ar, slist, 3, 0);
	asfd_mock_read(asfd, &ar, 0, CMD_GEN, "sigs_end");

	asfd_assert_write(asfd, &aw, 0, CMD_WRAP_UP, "BOJ");
	asfd_assert_write(asfd, &aw, 0, CMD_GEN, "blk_requests_end");
	asfd_mock_read_no_op(asfd, &ar, 25600);
	asfd_mock_read(asfd, &ar, 0, CMD_GEN, "backup_end");

	setup_chfd_writes_from_slist(chfd, &cw, slist, 3, 0);
	asfd_mock_read_no_op(chfd, &cr, 25600);
	setup_chfd_reads_from_slist_blks_got(chfd, &cr, slist, 3, 0);
	asfd_mock_read_no_op(chfd, &cr, 25600);
	asfd_assert_write(chfd, &cw, 0, CMD_GEN, "sigs_end");
	asfd_assert_write(chfd, &cw, 0, CMD_MANIFEST, "utest_server_protocol2_backup_phase2/a_group/clients/utestclient/working/changed/00000000");
}

static void setup_asfds_happy_path_one_blk_per_file_no_dedup(
	struct asfd *asfd, struct asfd *chfd, struct slist *slist)
{
	int ar=0, aw=0, cr=0, cw=0;

	setup_writes_from_slist(asfd, &aw, slist);
	asfd_assert_write(asfd, &aw, 0, CMD_GEN, "requests_end");
	asfd_mock_read_no_op(asfd, &ar, 30);
	setup_reads_from_slist(asfd, &ar, slist, 1, 0);
	asfd_mock_read(asfd, &ar, 0, CMD_GEN, "sigs_end");

	setup_writes_from_slist_blk_requests(asfd, &aw, slist, 1, 0);
	asfd_assert_write(asfd, &aw, 0, CMD_GEN, "blk_requests_end");
	asfd_mock_read_no_op(asfd, &ar, 60);
	setup_reads_from_slist_blks(asfd, &ar, slist, 1, 0);
	asfd_mock_read(asfd, &ar, 0, CMD_GEN, "backup_end");

	setup_chfd_writes_from_slist(chfd, &cw, slist, 1, 0);
	asfd_mock_read_no_op(chfd, &cr, 60);
	setup_chfd_reads_from_slist_blks_not_got(chfd, &cr, slist, 1, 0);
	asfd_mock_read_no_op(chfd, &cr, 60);
	asfd_assert_write(chfd, &cw, 0, CMD_GEN, "sigs_end");
}

static void setup_asfds_happy_path_one_blk_per_file_no_dedup_big(
	struct asfd *asfd, struct asfd *chfd, struct slist *slist)
{
	int ar=0, aw=0, cr=0, cw=0;

	setup_writes_from_slist(asfd, &aw, slist);
	asfd_assert_write(asfd, &aw, 0, CMD_GEN, "requests_end");
	asfd_mock_read_no_op(asfd, &ar, 12800);
	setup_reads_from_slist(asfd, &ar, slist, 1, 0);
	asfd_mock_read(asfd, &ar, 0, CMD_GEN, "sigs_end");

	setup_writes_from_slist_blk_requests(asfd, &aw, slist, 1, 0);
	asfd_assert_write(asfd, &aw, 0, CMD_GEN, "blk_requests_end");
	asfd_mock_read_no_op(asfd, &ar, 35600);
	setup_reads_from_slist_blks(asfd, &ar, slist, 1, 0);
	asfd_mock_read(asfd, &ar, 0, CMD_GEN, "backup_end");

	setup_chfd_writes_from_slist(chfd, &cw, slist, 1, 0);
	asfd_mock_read_no_op(chfd, &cr, 35600);
	setup_chfd_reads_from_slist_blks_not_got(chfd, &cr, slist, 1, 0);
	asfd_mock_read_no_op(chfd, &cr, 35600);
	asfd_assert_write(chfd, &cw, 0, CMD_GEN, "sigs_end");
	asfd_assert_write(chfd, &cw, 0, CMD_MANIFEST, "utest_server_protocol2_backup_phase2/a_group/clients/utestclient/working/changed/00000000");
}

static void setup_asfds_happy_path_three_blks_per_file_no_dedup(
	struct asfd *asfd, struct asfd *chfd, struct slist *slist)
{
	int ar=0, aw=0, cr=0, cw=0;

	setup_writes_from_slist(asfd, &aw, slist);
	asfd_assert_write(asfd, &aw, 0, CMD_GEN, "requests_end");
	asfd_mock_read_no_op(asfd, &ar, 200);
	setup_reads_from_slist(asfd, &ar, slist, 3, 0);
	asfd_mock_read(asfd, &ar, 0, CMD_GEN, "sigs_end");

	setup_writes_from_slist_blk_requests(asfd, &aw, slist, 3, 0);
	asfd_assert_write(asfd, &aw, 0, CMD_GEN, "blk_requests_end");
	asfd_mock_read_no_op(asfd, &ar, 1000);
	setup_reads_from_slist_blks(asfd, &ar, slist, 3, 0);
	asfd_mock_read(asfd, &ar, 0, CMD_GEN, "backup_end");

	setup_chfd_writes_from_slist(chfd, &cw, slist, 3, 0);
	asfd_mock_read_no_op(chfd, &cr, 1000);
	setup_chfd_reads_from_slist_blks_not_got(chfd, &cr, slist, 3, 0);
	asfd_mock_read_no_op(chfd, &cr, 1000);
	asfd_assert_write(chfd, &cw, 0, CMD_GEN, "sigs_end");
}

static void setup_asfds_happy_path_three_blks_per_file_no_dedup_big(
	struct asfd *asfd, struct asfd *chfd, struct slist *slist)
{
	int ar=0, aw=0, cr=0, cw=0;

	setup_writes_from_slist(asfd, &aw, slist);
	asfd_assert_write(asfd, &aw, 0, CMD_GEN, "requests_end");
	asfd_mock_read_no_op(asfd, &ar, 12800);
	setup_reads_from_slist(asfd, &ar, slist, 3, 0);
	asfd_mock_read(asfd, &ar, 0, CMD_GEN, "sigs_end");

	setup_writes_from_slist_blk_requests(asfd, &aw, slist, 3, 0);
	asfd_assert_write(asfd, &aw, 0, CMD_GEN, "blk_requests_end");
	asfd_mock_read_no_op(asfd, &ar, 25600);
	setup_reads_from_slist_blks(asfd, &ar, slist, 3, 0);
	asfd_mock_read(asfd, &ar, 0, CMD_GEN, "backup_end");

	setup_chfd_writes_from_slist(chfd, &cw, slist, 3, 0);
	asfd_mock_read_no_op(chfd, &cr, 25600);
	setup_chfd_reads_from_slist_blks_not_got(chfd, &cr, slist, 3, 0);
	asfd_mock_read_no_op(chfd, &cr, 25600);
	asfd_assert_write(chfd, &cw, 0, CMD_GEN, "sigs_end");
	asfd_assert_write(chfd, &cw, 0, CMD_MANIFEST, "utest_server_protocol2_backup_phase2/a_group/clients/utestclient/working/changed/00000000");
}

static void setup_asfds_happy_path_one_blk_per_file_no_dedup_interrupt(
	struct asfd *asfd, struct asfd *chfd, struct slist *slist)
{
	int ar=0, aw=0, cr=0, cw=0;

	setup_writes_from_slist(asfd, &aw, slist);
	asfd_assert_write(asfd, &aw, 0, CMD_GEN, "requests_end");
	asfd_mock_read_no_op(asfd, &ar, 30);
	setup_reads_from_slist(asfd, &ar, slist, 1, 2 /* interrupt */);
	asfd_mock_read(asfd, &ar, 0, CMD_GEN, "sigs_end");

	setup_writes_from_slist_blk_requests(asfd,
		&aw, slist, 1, 2 /* interrupt */);
	asfd_assert_write(asfd, &aw, 0, CMD_GEN, "blk_requests_end");
	asfd_mock_read_no_op(asfd, &ar, 60);
	setup_reads_from_slist_blks(asfd, &ar, slist, 1, 2 /* interrupt */);
	asfd_mock_read(asfd, &ar, 0, CMD_GEN, "backup_end");

	setup_chfd_writes_from_slist(chfd, &cw, slist, 1, 2 /* interrupt */);
	asfd_mock_read_no_op(chfd, &cr, 60);
	setup_chfd_reads_from_slist_blks_not_got(chfd,
		&cr, slist, 1, 2 /* interrupt */);
	asfd_mock_read_no_op(chfd, &cr, 60);
	asfd_assert_write(chfd, &cw, 0, CMD_GEN, "sigs_end");
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
	prng_init(0);
	base64_init();
	hexmap_init();
	setup(&as, &sdirs, &confs);
	asfd=asfd_mock_setup(&areads, &awrites);
	chfd=asfd_mock_setup(&creads, &cwrites);
	fail_unless((asfd->desc=strdup_w("a", __func__))!=NULL);
	fail_unless((chfd->desc=strdup_w("c", __func__))!=NULL);
	as->asfd_add(as, asfd);
	as->asfd_add(as, chfd);
	as->read_write=async_read_write_callback;

	if(manio_entries)
		slist=build_manifest(sdirs->phase1data,
			PROTO_2, manio_entries, 1 /*phase*/);
	setup_asfds_callback(asfd, chfd, slist);

	fail_unless(do_backup_phase2_server_protocol2(
		as,
		chfd,
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

START_TEST(asfds_empty)
{
	run_test(0, 0, async_rw_simple, setup_asfds_empty);
}
END_TEST

START_TEST(asfds_empty_and_messages)
{
	run_test(0, 0, async_rw_simple, setup_asfds_empty_and_messages);
}
END_TEST

START_TEST(asfds_data_too_soon)
{
	run_test(-1, 0, async_rw_simple, setup_asfds_data_too_soon);
}
END_TEST

START_TEST(asfds_write_error)
{
	run_test(-1, 0, async_rw_simple, setup_asfds_write_error);
}
END_TEST

START_TEST(asfds_write_error_chfd)
{
	run_test(-1, 0, async_rw_simple, setup_asfds_write_error_chfd);
}
END_TEST

START_TEST(asfds_read_error)
{
	run_test(-1, 0, async_rw_simple, setup_asfds_read_error);
}
END_TEST

START_TEST(asfds_read_error_chfd)
{
	run_test(-1, 0, async_rw_both, setup_asfds_read_error_chfd);
}
END_TEST

START_TEST(asfds_chfd_bad_cmd)
{
	run_test(-1, 0, async_rw_both, setup_asfds_chfd_bad_cmd);
}
END_TEST

START_TEST(asfds_no_sigs_from_client)
{
	run_test(-1, 20, async_rw_simple, setup_asfds_no_sigs_from_client);
}
END_TEST

START_TEST(asfds_happy_path_one_blk_per_file_full_dedup)
{
	run_test(0, 20, async_rw_both,
		setup_asfds_happy_path_one_blk_per_file_full_dedup);
}
END_TEST

START_TEST(asfds_happy_path_one_blk_per_file_full_dedup_big)
{
	run_test(0, 12800, async_rw_both,
		setup_asfds_happy_path_one_blk_per_file_full_dedup_big);
}
END_TEST

START_TEST(asfds_happy_path_three_blks_per_file_full_dedup)
{
	run_test(0, 20, async_rw_both,
		setup_asfds_happy_path_three_blks_per_file_full_dedup);
}
END_TEST

START_TEST(asfds_happy_path_three_blks_per_file_full_dedup_big)
{
	run_test(0, 4000, async_rw_both,
		setup_asfds_happy_path_three_blks_per_file_full_dedup_big);
}
END_TEST

START_TEST(asfds_happy_path_one_blk_per_file_no_dedup)
{
	run_test(0, 20, async_rw_both,
		setup_asfds_happy_path_one_blk_per_file_no_dedup);
}
END_TEST

START_TEST(asfds_happy_path_one_blk_per_file_no_dedup_big)
{
	run_test(0, 12800, async_rw_both,
		setup_asfds_happy_path_one_blk_per_file_no_dedup_big);
}
END_TEST

START_TEST(asfds_happy_path_three_blks_per_file_no_dedup)
{
	run_test(0, 20, async_rw_both,
		setup_asfds_happy_path_three_blks_per_file_no_dedup);
}
END_TEST

START_TEST(asfds_happy_path_three_blks_per_file_no_dedup_big)
{
	run_test(0, 4000, async_rw_both,
		setup_asfds_happy_path_three_blks_per_file_no_dedup_big);
}
END_TEST

START_TEST(asfds_happy_path_one_blk_per_file_no_dedup_interrupt)
{
	run_test(0, 20, async_rw_both,
		setup_asfds_happy_path_one_blk_per_file_no_dedup_interrupt);
}
END_TEST

Suite *suite_server_protocol2_backup_phase2(void)
{
	Suite *s;
	TCase *tc_core;

	s=suite_create("server_protocol2_backup_phase2");

	tc_core=tcase_create("Core");
	tcase_set_timeout(tc_core, 60);

	tcase_add_test(tc_core, test_phase2_unset_as_sdirs_confs);
	tcase_add_test(tc_core, test_phase2_unset_sdirs_confs);
	tcase_add_test(tc_core, test_phase2_unset_confs);
	tcase_add_test(tc_core, test_phase2_unset_sdirs);
	tcase_add_test(tc_core, test_phase2_unset_asfd);
	tcase_add_test(tc_core, test_phase2_unset_chfd);

	tcase_add_test(tc_core, asfds_empty);
	tcase_add_test(tc_core, asfds_empty_and_messages);
	tcase_add_test(tc_core, asfds_data_too_soon);
	tcase_add_test(tc_core, asfds_write_error);
	tcase_add_test(tc_core, asfds_write_error_chfd);
	tcase_add_test(tc_core, asfds_read_error);
	tcase_add_test(tc_core, asfds_read_error_chfd);
	tcase_add_test(tc_core, asfds_chfd_bad_cmd);
	tcase_add_test(tc_core, asfds_no_sigs_from_client);

	tcase_add_test(tc_core,
		asfds_happy_path_one_blk_per_file_full_dedup);
	tcase_add_test(tc_core,
		asfds_happy_path_one_blk_per_file_full_dedup_big);
	tcase_add_test(tc_core,
		asfds_happy_path_three_blks_per_file_full_dedup);
	tcase_add_test(tc_core,
		asfds_happy_path_three_blks_per_file_full_dedup_big);

	tcase_add_test(tc_core,
		asfds_happy_path_one_blk_per_file_no_dedup);
	tcase_add_test(tc_core,
		asfds_happy_path_one_blk_per_file_no_dedup_big);
	tcase_add_test(tc_core,
		asfds_happy_path_three_blks_per_file_no_dedup);
	tcase_add_test(tc_core,
		asfds_happy_path_three_blks_per_file_no_dedup_big);

	tcase_add_test(tc_core,
		asfds_happy_path_one_blk_per_file_no_dedup_interrupt);

	suite_add_tcase(s, tc_core);

	return s;
}
