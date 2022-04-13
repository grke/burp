#include "../test.h"
#include "../builders/build.h"
#include "../../src/action.h"
#include "../../src/alloc.h"
#include "../../src/asfd.h"
#include "../../src/attribs.h"
#include "../../src/base64.h"
#include "../../src/bfile.h"
#include "../../src/cmd.h"
#include "../../src/conf.h"
#include "../../src/conffile.h"
#include "../../src/client/restore.h"
#include "../../src/fsops.h"
#include "../../src/iobuf.h"
#include "../../src/slist.h"
#include "../builders/build_asfd_mock.h"
#include "../builders/build_file.h"

#define BASE	"utest_client_restore"

static struct ioevent_list reads;
static struct ioevent_list writes;

static char *absolute(const char *fname)
{
	static char path[1024];
	char cwd[512];
	fail_unless(getcwd(cwd, sizeof(cwd))!=NULL);
	snprintf(path, sizeof(path), "%s/%s/%s", cwd, BASE, fname);
	return path;
}

static void tear_down(struct asfd **asfd, struct conf ***confs)
{
	asfd_free(asfd);
	confs_free(confs);
	asfd_mock_teardown(&reads, &writes);
//printf("%d %d\n", alloc_count, free_count);
	alloc_check();
	fail_unless(recursive_delete(BASE)==0);
}

static void setup_bad_read(struct asfd *asfd, struct slist *slist)
{
	int r=0; int w=0;
	asfd_assert_write(asfd, &w, 0, CMD_GEN, "restore :");
	asfd_mock_read(asfd, &r, 0, CMD_GEN, "ok");
	asfd_mock_read(asfd, &r, -1, CMD_GEN, "blah");
}

static void setup_proto1_no_files(struct asfd *asfd, struct slist *slist)
{
	int r=0; int w=0;
	asfd_assert_write(asfd, &w, 0, CMD_GEN, "restore :");
	asfd_mock_read(asfd, &r, 0, CMD_GEN, "ok");
	asfd_mock_read(asfd, &r, 0, CMD_GEN, "restoreend");
	asfd_assert_write(asfd, &w, 0, CMD_GEN, "restoreend ok");
}

static void setup_proto1_no_datapth(struct asfd *asfd, struct slist *slist)
{
	int r=0; int w=0;
	uint32_t l;
	char *path;

	path=absolute("afile");
	l=(uint32_t)strlen(path);
	char expected[512];
	snprintf(expected, sizeof(expected), "datapth not supplied for f:%04X:%s in restore_switch_protocol1\n", l, path);
	asfd_assert_write(asfd, &w, 0, CMD_GEN, "restore :");
	asfd_mock_read(asfd, &r, 0, CMD_GEN, "ok");
	asfd_mock_read(asfd, &r, 0, CMD_ATTRIBS, "attribs");
	asfd_mock_read(asfd, &r, 0, CMD_FILE, path);
	asfd_assert_write(asfd, &w, 0, CMD_ERROR, expected);
}

static void setup_proto1_no_attribs(struct asfd *asfd, struct slist *slist)
{
	int r=0; int w=0;
	asfd_assert_write(asfd, &w, 0, CMD_GEN, "restore :");
	asfd_mock_read(asfd, &r, 0, CMD_GEN, "ok");
	asfd_mock_read(asfd, &r, 0, CMD_DATAPTH, "datapth");
	asfd_mock_read(asfd, &r, 0, CMD_FILE, absolute("afile"));
	asfd_assert_write(asfd, &w, 0, CMD_ERROR, "read cmd with no attribs");
}

static void setup_proto1_some_things(struct asfd *asfd, struct slist *slist)
{
	struct sbuf *s;
	struct stat statp_dir;
	struct stat statp_file;
	int r=0; int w=0;
	fail_unless(!lstat(BASE, &statp_dir));
	fail_unless(!lstat(BASE "/burp.conf", &statp_file));
	asfd_assert_write(asfd, &w, 0, CMD_GEN, "restore :");
	asfd_mock_read(asfd, &r, 0, CMD_GEN, "ok");
	for(s=slist->head; s; s=s->next)
	{
		s->winattr=0;
		s->compression=0;
		if(s->path.cmd==CMD_DIRECTORY)
		{
			memcpy(&s->statp, &statp_dir, sizeof(statp_dir));
			attribs_encode(s);
		}
		if(sbuf_is_link(s))
		{
			char path[256];
			if(s->path.cmd==CMD_HARD_LINK)
				snprintf(path, sizeof(path), "%s", s->link.buf);
			else
			{
				char *cp;
				snprintf(path, sizeof(path), "%s", s->path.buf);
				fail_unless((cp=strrchr(path, '/'))!=NULL);
				cp++;
				snprintf(cp, strlen(s->link.buf)+1, "%s",
					s->link.buf);
			}
			build_file(path, NULL);
			
			memcpy(&s->statp, &statp_file, sizeof(statp_file));
			attribs_encode(s);
			asfd_mock_read_iobuf(asfd, &r, 0, &s->attr);
			asfd_mock_read_iobuf(asfd, &r, 0, &s->path);
			asfd_mock_read_iobuf(asfd, &r, 0, &s->link);
		}
		else if(sbuf_is_filedata(s))
		{
			struct iobuf rbuf;
			// The string "data" gzipped.
			unsigned char gzipped_data[27] = {
				0x1f, 0x8b, 0x08, 0x08, 0xb4, 0x1e, 0x7f, 0x56,
				0x00, 0x03, 0x79, 0x00, 0x4b, 0x49, 0x2c, 0x49,
				0xe4, 0x02, 0x00, 0x82, 0xc5, 0xc1, 0xe6, 0x05,
				0x00, 0x00, 0x00
			};
			memcpy(&s->statp, &statp_file, sizeof(statp_file));
			attribs_encode(s);
			asfd_mock_read(asfd, &r,
				0, CMD_DATAPTH, s->path.buf);
			asfd_mock_read_iobuf(asfd, &r, 0, &s->attr);
			asfd_mock_read_iobuf(asfd, &r,
				0, &s->path);
			// Protocol1 always sends it gzipped.
			iobuf_set(&rbuf, CMD_APPEND,
				(char *)gzipped_data, sizeof(gzipped_data));
			asfd_mock_read_iobuf(asfd, &r, 0, &rbuf);
			asfd_mock_read(asfd, &r,
				0, CMD_END_FILE, "0:19201273128");
		}
	}
	asfd_mock_read(asfd, &r, 0, CMD_GEN, "restoreend");
	asfd_assert_write(asfd, &w, 0, CMD_GEN, "restoreend ok");
}

static struct conf **setup_conf(void)
{
	struct conf **confs=NULL;
	fail_unless((confs=confs_alloc())!=NULL);
	fail_unless(!confs_init(confs));
	return confs;
}

static void run_test(int expected_ret,
	int slist_entries,
	void setup_callback(struct asfd *asfd, struct slist *slist))
{
	int result;
	struct slist *slist=NULL;
	const char *conffile=BASE "/burp.conf";
	struct asfd *asfd;
	struct conf **confs;
	char buf[4096];

	snprintf(buf, sizeof(buf), MIN_CLIENT_CONF "restoreprefix=/\n");

	base64_init();

	asfd=asfd_mock_setup(&reads, &writes);
	confs=setup_conf();

	fail_unless(recursive_delete(BASE)==0);

	build_file(conffile, buf);
	fail_unless(!conf_load_global_only(conffile, confs));

	if(slist_entries)
		slist=build_slist_phase1(BASE, slist_entries);

	setup_callback(asfd, slist);

	result=do_restore_client(asfd, confs, ACTION_RESTORE);
	fail_unless(result==expected_ret);

	slist_free(&slist);
	tear_down(&asfd, &confs);
}

START_TEST(test_restore_proto1_bad_read)
{
	run_test(-1, 0, setup_bad_read);
}
END_TEST

START_TEST(test_restore_proto1_no_files)
{
	run_test( 0, 0, setup_proto1_no_files);
}
END_TEST

START_TEST(test_restore_proto1_no_datapth)
{
	run_test(-1, 0, setup_proto1_no_datapth);
}
END_TEST

START_TEST(test_restore_proto1_no_attribs)
{
	run_test(-1, 0, setup_proto1_no_attribs);
}
END_TEST

START_TEST(test_restore_proto1_some_things)
{
	run_test(0, 10, setup_proto1_some_things);
}
END_TEST

struct sdata
{
	const char *input;
	const char *strip;
	const char *expected;
};

static struct sdata s[] = {
	{ "/path/to/a/file", "/to/a", "/path/file" },
	{ "/path/to/a/file/to/a/foo", "/to/a", "/path/file/to/a/foo" },
	{ "/path/to/a/file", "/path/to/a/file", "/path/to/a/file" },
	{ "/path/to/a/file", "/", "path/to/a/file" },
	{ "/path/to/a/file/", "/path/to/a/file", "/" },
	{ "/path/to/a/file", "", "/path/to/a/file" },
	{ "/path/to/a/file", NULL, "/path/to/a/file" }
};

START_TEST(test_strip_from_path)
{
	FOREACH(s)
	{
		char input[256];
		snprintf(input, sizeof(input), "%s", s[i].input);
		strip_from_path(input, s[i].strip);
		fail_unless(!strcmp(input, s[i].expected));
	}
}
END_TEST

Suite *suite_client_restore(void)
{
	Suite *s;
	TCase *tc_core;

	s=suite_create("client_restore");

	tc_core=tcase_create("Core");
	tcase_set_timeout(tc_core, 60);

	tcase_add_test(tc_core, test_restore_proto1_bad_read);
	tcase_add_test(tc_core, test_restore_proto1_no_files);
	tcase_add_test(tc_core, test_restore_proto1_no_datapth);
	tcase_add_test(tc_core, test_restore_proto1_no_attribs);
	tcase_add_test(tc_core, test_restore_proto1_some_things);

	tcase_add_test(tc_core, test_strip_from_path);

	suite_add_tcase(s, tc_core);

	return s;
}
