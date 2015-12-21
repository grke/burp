#include "../test.h"
#include "../../src/action.h"
#include "../../src/alloc.h"
#include "../../src/asfd.h"
#include "../../src/bfile.h"
#include "../../src/cmd.h"
#include "../../src/conf.h"
#include "../../src/conffile.h"
#include "../../src/client/restore.h"
#include "../../src/fsops.h"
#include "../../src/iobuf.h"
#include "../builders/build_asfd_mock.h"
#include "../builders/build_file.h"

#define BASE	"utest_restore"

static struct ioevent_list reads;
static struct ioevent_list writes;

static void tear_down(struct asfd **asfd, struct conf ***confs)
{
	asfd_free(asfd);
	confs_free(confs);
	asfd_mock_teardown(&reads, &writes);
//printf("%d %d\n", alloc_count, free_count);
	alloc_check();
	fail_unless(recursive_delete(BASE)==0);
}

static void setup_proto1_bad_read(struct asfd *asfd)
{
	int r=0; int w=0;
	asfd_assert_write(asfd, &w, 0, CMD_GEN, "restore :");
	asfd_mock_read(asfd, &r, 0, CMD_GEN, "ok");
	asfd_mock_read(asfd, &r, -1, CMD_GEN, "blah");
}

static void setup_proto1_no_files(struct asfd *asfd)
{
	int r=0; int w=0;
	asfd_assert_write(asfd, &w, 0, CMD_GEN, "restore :");
	asfd_mock_read(asfd, &r, 0, CMD_GEN, "ok");
	asfd_mock_read(asfd, &r, 0, CMD_GEN, "restoreend");
	asfd_assert_write(asfd, &w, 0, CMD_GEN, "restoreend_ok");
}

static void setup_proto1_no_datapth(struct asfd *asfd)
{
	int r=0; int w=0;
	asfd_assert_write(asfd, &w, 0, CMD_GEN, "restore :");
	asfd_mock_read(asfd, &r, 0, CMD_GEN, "ok");
	asfd_mock_read(asfd, &r, 0, CMD_ATTRIBS, "attribs");
	asfd_mock_read(asfd, &r, 0, CMD_FILE, BASE "/afile");
	asfd_assert_write(asfd, &w, 0, CMD_ERROR, "datapth not supplied for f:utest_restore/afile in restore_switch_protocol1\n");
}

static void setup_proto1_no_attribs(struct asfd *asfd)
{
	int r=0; int w=0;
	asfd_assert_write(asfd, &w, 0, CMD_GEN, "restore :");
	asfd_mock_read(asfd, &r, 0, CMD_GEN, "ok");
	asfd_mock_read(asfd, &r, 0, CMD_DATAPTH, "datapth");
	asfd_mock_read(asfd, &r, 0, CMD_FILE, BASE "/afile");
	asfd_assert_write(asfd, &w, 0, CMD_ERROR, "read cmd with no attribs");
}

static struct conf **setup_conf(void)
{
	struct conf **confs=NULL;
	fail_unless((confs=confs_alloc())!=NULL);
	fail_unless(!confs_init(confs));
	return confs;
}

static void run_test_proto1(int expected_ret,
	void setup_callback(struct asfd *asfd))
{
	int result;
	const char *conffile=BASE "/burp.conf";
	struct asfd *asfd=asfd_mock_setup(&reads, &writes);
	struct conf **confs=setup_conf();
	const char *buf=MIN_CLIENT_CONF
		"protocol=1\n";

	fail_unless(recursive_delete(BASE)==0);

	build_file(conffile, buf);
	fail_unless(!conf_load_global_only(conffile, confs));

	setup_callback(asfd);

	result=do_restore_client(asfd, confs,
		ACTION_RESTORE, 0 /* vss_restore */);
	fail_unless(result==expected_ret);

	tear_down(&asfd, &confs);
}

START_TEST(test_restore_proto1_bad_read)
{
	run_test_proto1(-1, setup_proto1_bad_read);
}
END_TEST

START_TEST(test_restore_proto1_no_files)
{
	run_test_proto1( 0, setup_proto1_no_files);
}
END_TEST

START_TEST(test_restore_proto1_no_datapth)
{
	run_test_proto1(-1, setup_proto1_no_datapth);
}
END_TEST

START_TEST(test_restore_proto1_no_attribs)
{
	run_test_proto1(-1, setup_proto1_no_attribs);
}
END_TEST

Suite *suite_client_restore(void)
{
	Suite *s;
	TCase *tc_core;

	s=suite_create("client_restore");

	tc_core=tcase_create("Core");

	tcase_add_test(tc_core, test_restore_proto1_bad_read);
	tcase_add_test(tc_core, test_restore_proto1_no_files);
	tcase_add_test(tc_core, test_restore_proto1_no_datapth);
	tcase_add_test(tc_core, test_restore_proto1_no_attribs);
	suite_add_tcase(s, tc_core);

	return s;
}
