#include "../test.h"
#include "../builders/build_file.h"
#include "../prng.h"
#include "../../src/action.h"
#include "../../src/alloc.h"
#include "../../src/asfd.h"
#include "../../src/async.h"
#include "../../src/attribs.h"
#include "../../src/base64.h"
#include "../../src/bu.h"
#include "../../src/cmd.h"
#include "../../src/cntr.h"
#include "../../src/fsops.h"
#include "../../src/hexmap.h"
#include "../../src/iobuf.h"
#include "../../src/protocol2/blk.h"
#include "../../src/regexp.h"
#include "../../src/server/manio.h"
#include "../../src/server/restore.h"
#include "../../src/server/sdirs.h"
#include "../../src/slist.h"
#include "../builders/build.h"
#include "../builders/build_asfd_mock.h"

#define BASE	"utest_server_restore"

static struct ioevent_list reads;
static struct ioevent_list writes;

static void do_sdirs_init(struct sdirs *sdirs, enum protocol protocol)
{
	fail_unless(!sdirs_init(sdirs, protocol,
		BASE, // directory
		"utestclient", // cname
		NULL, // client_lockdir
		"a_group", // dedup_group
		NULL // manual_delete
       ));
}

static struct sdirs *setup_sdirs(enum protocol protocol)
{
	struct sdirs *sdirs;
	fail_unless((sdirs=sdirs_alloc())!=NULL);
	do_sdirs_init(sdirs, protocol);
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

static void setup(enum protocol protocol, struct async **as,
	struct sdirs **sdirs, struct conf ***confs)
{
	if(as) *as=setup_async();
	if(sdirs) *sdirs=setup_sdirs(protocol);
	if(confs) *confs=setup_conf();
	fail_unless(!recursive_delete(BASE));
}

static void tear_down(struct async **as, struct asfd **asfd,
	struct sdirs **sdirs, struct conf ***confs)
{
	async_free(as);
	asfd_free(asfd);
	sdirs_free(sdirs);
	asfd_mock_teardown(&reads, &writes);
	confs_free(confs);
//printf("%d %d\n", alloc_count, free_count);
	alloc_check();
	fail_unless(!recursive_delete(BASE));
}

// Tests that the client gets sent a suitable message when the server tried
// to restore on a bad regex.
static void setup_bad_regex(struct asfd *asfd)
{
	int w=0;
	asfd_assert_write(asfd,
		&w, 0, CMD_ERROR, "unable to compile regex: *\n");
}

START_TEST(test_send_regex_failure)
{
	struct asfd *asfd;
	struct conf **confs=NULL;
	fail_unless((confs=confs_alloc())!=NULL);
	fail_unless(!confs_init(confs));
	set_string(confs[OPT_REGEX], "*");
	set_string(confs[OPT_BACKUP], "1");

	asfd=asfd_mock_setup(&reads, &writes);
	setup_bad_regex(asfd);
	fail_unless(do_restore_server(
		asfd,
		NULL, // sdirs
		ACTION_RESTORE,
		1, // srestore
		NULL, // dir_for_notify
		confs)==-1);

	tear_down(NULL, &asfd, NULL, &confs);
}
END_TEST

static struct sd sd1[] = {
	{ "0000001 1970-01-01 00:00:00", 1, 1, BU_CURRENT },
};

static int async_rw_simple(struct async *as)
{
	return as->asfd->read(as->asfd);
}

static void run_test(int expected_ret,
	enum protocol protocol,
	int manio_entries,
	int blocks_per_file,
	void setup_asfds_callback(struct asfd *asfd, struct slist *slist))
{
        struct async *as;
        struct asfd *asfd;
        struct sdirs *sdirs;
        struct conf **confs;
        struct slist *slist=NULL;
	char *dir_for_notify=NULL;
        prng_init(0);
        base64_init();
        hexmap_init();
        setup(protocol, &as, &sdirs, &confs);
	set_string(confs[OPT_BACKUP], "1");
	set_protocol(confs, protocol);
        asfd=asfd_mock_setup(&reads, &writes);
	as->asfd_add(as, asfd);
	as->read_write=async_rw_simple;
	as->read_quick=async_rw_simple;
	asfd->as=as;

	build_storage_dirs(sdirs, sd1, ARR_LEN(sd1));
	if(manio_entries)
	{
		struct sbuf *s;
		if(protocol==PROTO_2)
			slist=build_manifest_with_data_files(sdirs->cmanifest,
				sdirs->data, manio_entries, blocks_per_file);
		else
		{
			slist=build_manifest(sdirs->cmanifest,
				protocol, manio_entries, 0 /*phase*/);
			for(s=slist->head; s; s=s->next)
			{
				char path[256];
				if(!sbuf_is_filedata(s))
					continue;
				snprintf(path, sizeof(path), "%s/%s%s",
					sdirs->currentdata,
					TREE_DIR, s->path.buf);
				build_file(path, "data");
			}
		}
	}
	setup_asfds_callback(asfd, slist);

	fail_unless(do_restore_server(
		asfd,
		sdirs,
		ACTION_RESTORE,
		0, // srestore
		&dir_for_notify,
		confs
	)==expected_ret);

	if(!expected_ret)
	{
		// FIX THIS: Should check for the presence and correctness of
		// changed and unchanged manios.
	}
	slist_free(&slist);
	free_w(&dir_for_notify);
	tear_down(&as, &asfd, &sdirs, &confs);
}

static unsigned char get_gzip_os_type(void)
{
	// Determine the gzip os type byte by creating a gzip file and then
	// reading it.
	struct fzp *zp;
	char buf[32];

	fail_unless((zp=fzp_gzopen(BASE "/file.gz", "w"))!=NULL);
	fail_unless(fzp_printf(zp, "test")==4);
	fail_unless(!fzp_close(&zp));

	fail_unless((zp=fzp_open(BASE "/file.gz", "r"))!=NULL);
	fail_unless(fzp_read(zp, buf, 10)==10);
	fail_unless(!fzp_close(&zp));

	return buf[9];
}

static void setup_asfds_proto1_stuff(struct asfd *asfd, struct slist *slist)
{
	int r=0; int w=0;
	struct sbuf *s;

	unsigned char gzip_os_type=get_gzip_os_type();

	for(s=slist->head; s; s=s->next)
	{
		if(sbuf_is_link(s))
		{
			asfd_assert_write_iobuf(asfd, &w, 0, &s->attr);
			asfd_assert_write_iobuf(asfd, &w, 0, &s->path);
			asfd_assert_write_iobuf(asfd, &w, 0, &s->link);
		}
		else if(sbuf_is_filedata(s))
		{
			struct iobuf wbuf;
			// The string "data" gzipped.
			unsigned char gzipped_data1[10] = {
				0x1f, 0x8b, 0x08, 0, 0,
				0, 0, 0, 0x02, 0
			};

			gzipped_data1[9]=gzip_os_type;

			unsigned char gzipped_data2[14] = {
				0x4b, 0x49, 0x2c, 0x49, 0x04, 0x00, 0x63,
				0xf3, 0xf3, 0xad, 0x04, 0x00, 0x00, 0x00
			};
			asfd_assert_write_iobuf(asfd, &w,
				0, &s->protocol1->datapth);
			asfd_assert_write_iobuf(asfd, &w, 0, &s->attr);
			asfd_assert_write_iobuf(asfd, &w, 0, &s->path);
			if(sbuf_is_encrypted(s))
			{
				// Encrypted files get sent as is.
				asfd_assert_write(asfd, &w, 0, CMD_APPEND,
					"data");
				asfd_assert_write(asfd, &w, 0, CMD_END_FILE,
					"4:8d777f385d3dfec8815d20f7496026dc");
				continue;
			}
			// Protocol1 always sends it gzipped.
			iobuf_set(&wbuf, CMD_APPEND,
				(char *)gzipped_data1, sizeof(gzipped_data1));
			asfd_assert_write_iobuf(asfd, &w, 0, &wbuf);
			iobuf_set(&wbuf, CMD_APPEND,
				(char *)gzipped_data2, sizeof(gzipped_data2));
			asfd_assert_write_iobuf(asfd, &w, 0, &wbuf);
			asfd_assert_write(asfd, &w, 0, CMD_END_FILE,
				"4:8d777f385d3dfec8815d20f7496026dc");
		}
		else
		{
			asfd_assert_write_iobuf(asfd, &w, 0, &s->attr);
			asfd_assert_write_iobuf(asfd, &w, 0, &s->path);
		}
	}
	asfd_assert_write(asfd, &w, 0, CMD_GEN, "restoreend");
	asfd_mock_read_no_op(asfd, &r, 100);
	asfd_mock_read(asfd, &r, 0, CMD_GEN, "restoreend ok");
}

START_TEST(test_proto1_stuff)
{
	run_test(0, PROTO_1, 10, 0, setup_asfds_proto1_stuff);
}
END_TEST

static void setup_asfds_proto2_stuff(struct asfd *asfd, struct slist *slist)
{
	int r=0; int w=0;
	struct sbuf *s;
	asfd_assert_write(asfd, &w, 0, CMD_GEN, "restore_stream");
	asfd_mock_read(asfd, &r, 0, CMD_GEN, "restore_stream_ok");
	for(s=slist->head; s; s=s->next)
	{
		if(sbuf_is_link(s))
		{
			asfd_assert_write_iobuf(asfd, &w, 0, &s->attr);
			asfd_assert_write_iobuf(asfd, &w, 0, &s->path);
			asfd_assert_write_iobuf(asfd, &w, 0, &s->link);
		}
		else if(sbuf_is_filedata(s))
		{
			struct blk *b;
			asfd_assert_write_iobuf(asfd, &w, 0, &s->attr);
			asfd_assert_write_iobuf(asfd, &w, 0, &s->path);
			for(b=s->protocol2->bstart;
			  b && b!=s->protocol2->bend; b=b->next)
				asfd_assert_write(asfd,
					&w, 0, CMD_DATA, "data");
			asfd_assert_write(asfd, &w, 0, CMD_END_FILE, "0:0");
		}
		else
		{
			asfd_assert_write_iobuf(asfd, &w, 0, &s->attr);
			asfd_assert_write_iobuf(asfd, &w, 0, &s->path);
		}
	}
	asfd_assert_write(asfd, &w, 0, CMD_GEN, "restoreend");
	asfd_mock_read_no_op(asfd, &r, 300);
	asfd_mock_read(asfd, &r, 0, CMD_GEN, "restoreend ok");
}

static void setup_asfds_proto2_interrupt(struct asfd *asfd, struct slist *slist)
{
	int r=0; int w=0;
	struct sbuf *s;
	int count=0;
	asfd_assert_write(asfd, &w, 0, CMD_GEN, "restore_stream");
	asfd_mock_read(asfd, &r, 0, CMD_GEN, "restore_stream_ok");
	for(s=slist->head; s; s=s->next)
	{
		if(sbuf_is_link(s))
		{
			asfd_assert_write_iobuf(asfd, &w, 0, &s->attr);
			asfd_assert_write_iobuf(asfd, &w, 0, &s->path);
			asfd_assert_write_iobuf(asfd, &w, 0, &s->link);
			asfd_mock_read_no_op(asfd, &r, 1);
		}
		else if(sbuf_is_filedata(s))
		{
			struct blk *b;
			asfd_assert_write_iobuf(asfd, &w, 0, &s->attr);
			asfd_assert_write_iobuf(asfd, &w, 0, &s->path);
			asfd_mock_read_no_op(asfd, &r, 1);
			if(count++==1)
			{
				asfd_assert_write(asfd,
					&w, 0, CMD_DATA, "data");
				asfd_assert_write(asfd,
					&w, 0, CMD_DATA, "data");
				asfd_mock_read_no_op(asfd, &r, 2);
				asfd_mock_read(asfd, &r, 0, CMD_INTERRUPT,
					s->path.buf);
				asfd_assert_write(asfd, &w, 0,
					CMD_END_FILE, "0:0");
				continue;
			}
			for(b=s->protocol2->bstart;
				b && b!=s->protocol2->bend; b=b->next)
			{
				asfd_assert_write(asfd,
					&w, 0, CMD_DATA, "data");
				asfd_mock_read_no_op(asfd, &r, 1);
			}
			asfd_assert_write(asfd, &w, 0, CMD_END_FILE, "0:0");
			asfd_mock_read_no_op(asfd, &r, 1);
		}
		else
		{
			asfd_assert_write_iobuf(asfd, &w, 0, &s->attr);
			asfd_assert_write_iobuf(asfd, &w, 0, &s->path);
			asfd_mock_read_no_op(asfd, &r, 1);
		}
	}
	asfd_assert_write(asfd, &w, 0, CMD_GEN, "restoreend");
	asfd_mock_read_no_op(asfd, &r, 200);
	asfd_mock_read(asfd, &r, 0, CMD_GEN, "restoreend ok");
}

static void setup_asfds_proto2_interrupt_no_match(struct asfd *asfd,
	struct slist *slist)
{
	int r=0; int w=0;
	struct sbuf *s;
	asfd_assert_write(asfd, &w, 0, CMD_GEN, "restore_stream");
	asfd_mock_read(asfd, &r, 0, CMD_GEN, "restore_stream_ok");
	asfd_mock_read_no_op(asfd, &r, 10);
	asfd_mock_read(asfd, &r, 0, CMD_INTERRUPT, "00000");
	asfd_mock_read(asfd, &r, 0, CMD_INTERRUPT, "00001");
	asfd_mock_read(asfd, &r, 0, CMD_INTERRUPT, "00002");
	for(s=slist->head; s; s=s->next)
	{
		if(sbuf_is_link(s))
		{
			asfd_assert_write_iobuf(asfd, &w, 0, &s->attr);
			asfd_assert_write_iobuf(asfd, &w, 0, &s->path);
			asfd_assert_write_iobuf(asfd, &w, 0, &s->link);
		}
		else if(sbuf_is_filedata(s))
		{
			struct blk *b;
			asfd_assert_write_iobuf(asfd, &w, 0, &s->attr);
			asfd_assert_write_iobuf(asfd, &w, 0, &s->path);
			for(b=s->protocol2->bstart;
			  b && b!=s->protocol2->bend; b=b->next)
				asfd_assert_write(asfd,
					&w, 0, CMD_DATA, "data");
			asfd_assert_write(asfd, &w, 0, CMD_END_FILE, "0:0");
		}
		else
		{
			asfd_assert_write_iobuf(asfd, &w, 0, &s->attr);
			asfd_assert_write_iobuf(asfd, &w, 0, &s->path);
		}
	}
	asfd_assert_write(asfd, &w, 0, CMD_GEN, "restoreend");
	asfd_mock_read_no_op(asfd, &r, 200);
	asfd_mock_read(asfd, &r, 0, CMD_GEN, "restoreend ok");
}

static void setup_asfds_proto2_interrupt_on_non_filedata(struct asfd *asfd,
	struct slist *slist)
{
	int r=0; int w=0;
	struct sbuf *s;
	asfd_assert_write(asfd, &w, 0, CMD_GEN, "restore_stream");
	asfd_mock_read(asfd, &r, 0, CMD_GEN, "restore_stream_ok");
	for(s=slist->head; s; s=s->next)
	{
		asfd_assert_write_iobuf(asfd, &w, 0, &s->attr);
		asfd_assert_write_iobuf(asfd, &w, 0, &s->path);
	}
	asfd_mock_read_no_op(asfd, &r, 1);
	asfd_mock_read(asfd, &r, 0, CMD_INTERRUPT, "00000");
	asfd_assert_write(asfd, &w, 0, CMD_GEN, "restoreend");
	asfd_mock_read_no_op(asfd, &r, 200);
	asfd_mock_read(asfd, &r, 0, CMD_GEN, "restoreend ok");
}

START_TEST(test_proto2_stuff)
{
	run_test(0, PROTO_2, 10, 5, setup_asfds_proto2_stuff);
}
END_TEST

START_TEST(test_proto2_interrupt)
{
	run_test(0, PROTO_2, 10, 100, setup_asfds_proto2_interrupt);
}
END_TEST

START_TEST(test_proto2_interrupt_no_match)
{
	run_test(0, PROTO_2, 10, 5, setup_asfds_proto2_interrupt_no_match);
}
END_TEST

START_TEST(test_proto2_interrupt_on_non_filedata)
{
	size_t s;
	for(s=0; s<SIZEOF_MANIFEST_CMDS; s++)
		manifest_cmds[s]=CMD_DIRECTORY;

	run_test(0, PROTO_2,
		2, 1, setup_asfds_proto2_interrupt_on_non_filedata);
}
END_TEST

static void setup_windows_restore_endfile(struct asfd *asfd,
	int client_is_windows)
{
	int r=0; int w=0;
	asfd_assert_write(asfd, &w, 0, CMD_GEN, "restore_stream");
	asfd_mock_read(asfd, &r, 0, CMD_GEN, "restore_stream_ok");
	asfd_mock_read_no_op(asfd, &r, 10);

	if(client_is_windows)
	{
		asfd_assert_write(asfd, &w, 0, CMD_ATTRIBS,
			" J A A A EP4 B A A A A A A BYMChy BYMChy BXih7j A W");
		asfd_assert_write(asfd, &w, 0, CMD_FILE, "C:/$Recycle.Bin");
		asfd_assert_write(asfd, &w, 0, CMD_END_FILE, "0:0");

		asfd_assert_write(asfd, &w, 0, CMD_ATTRIBS,
			" J A A A EP4 B A A A BAA A A BYMCnk BYMCnk BXic5o A A");
		asfd_assert_write(asfd, &w, 0, CMD_FILE, "C:/");
		asfd_assert_write(asfd, &w, 0, CMD_END_FILE, "0:0");
	}

	asfd_assert_write(asfd, &w, 0, CMD_GEN, "restoreend");
	asfd_mock_read_no_op(asfd, &r, 10);
	asfd_mock_read(asfd, &r, 0, CMD_GEN, "restoreend ok");
}

static void do_test_proto2_windows_restore_endfile(int client_is_windows)
{
	struct async *as;
	struct asfd *asfd;
	struct sdirs *sdirs;
	struct conf **confs;
	enum protocol protocol=PROTO_2;
	struct manio *manio=NULL;
	struct sbuf *sb=NULL;
	char *dir_for_notify=NULL;

	prng_init(0);
	base64_init();
	hexmap_init();
	setup(protocol, &as, &sdirs, &confs);
	set_string(confs[OPT_BACKUP], "1");
	set_int(confs[OPT_CLIENT_IS_WINDOWS], client_is_windows);
	set_protocol(confs, protocol);
	asfd=asfd_mock_setup(&reads, &writes);
	as->asfd_add(as, asfd);
	as->read_write=async_rw_simple;
	as->read_quick=async_rw_simple;
	asfd->as=as;

	build_storage_dirs(sdirs, sd1, ARR_LEN(sd1));
	manio=manio_open(sdirs->cmanifest, "wb", protocol);
	fail_unless(manio!=NULL);
	fail_unless((sb=sbuf_alloc(protocol))!=NULL);

	iobuf_from_str(&sb->attr, CMD_ATTRIBS,
		strdup_w(" J A A A EP4 B A A A BAA A A BYMCnk BYMCnk BXic5o A A", __func__));
	iobuf_from_str(&sb->path, CMD_FILE, strdup_w("C:/", __func__));
	iobuf_from_str(&sb->endfile, CMD_END_FILE, strdup_w("0:0", __func__));
	fail_unless(!manio_write_sbuf(manio, sb));
	sbuf_free(&sb);

	fail_unless((sb=sbuf_alloc(protocol))!=NULL);
	iobuf_from_str(&sb->attr, CMD_ATTRIBS,
		strdup_w(" J A A A EP4 B A A A A A A BYMChy BYMChy BXih7j A W", __func__));
	iobuf_from_str(&sb->path, CMD_FILE, strdup_w("C:/$Recycle.Bin", __func__));
	iobuf_from_str(&sb->endfile, CMD_END_FILE, strdup_w("0:0", __func__));
	fail_unless(!manio_write_sbuf(manio, sb));

	manio_close(&manio);

	setup_windows_restore_endfile(asfd, client_is_windows);

	fail_unless(do_restore_server(
		asfd,
		sdirs,
		ACTION_RESTORE,
		0, // srestore
		&dir_for_notify,
		confs)==0);

	sbuf_free(&sb);
	free_w(&dir_for_notify);
	tear_down(&as, &asfd, &sdirs, &confs);
}

START_TEST(test_proto2_windows_restore_endfile_windows)
{
	do_test_proto2_windows_restore_endfile(/*client_is_windows*/1);
}
END_TEST

START_TEST(test_proto2_windows_restore_endfile_not_windows)
{
	do_test_proto2_windows_restore_endfile(/*client_is_windows*/0);
}
END_TEST

Suite *suite_server_restore(void)
{
	Suite *s;
	TCase *tc_core;

	s=suite_create("server_restore");

	tc_core=tcase_create("Core");
	tcase_set_timeout(tc_core, 60);

	tcase_add_test(tc_core, test_proto1_stuff);
	tcase_add_test(tc_core, test_proto2_stuff);
	tcase_add_test(tc_core, test_send_regex_failure);
	tcase_add_test(tc_core, test_proto2_interrupt);
	tcase_add_test(tc_core, test_proto2_interrupt_no_match);
	tcase_add_test(tc_core, test_proto2_interrupt_on_non_filedata);
	tcase_add_test(tc_core, test_proto2_windows_restore_endfile_windows);
	tcase_add_test(tc_core, test_proto2_windows_restore_endfile_not_windows);

	suite_add_tcase(s, tc_core);

	return s;
}
