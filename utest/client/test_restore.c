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

static const char *basepath="utest_restore";

static struct ioevent_list reads;
static struct ioevent_list writes;

static void tear_down(struct asfd **asfd, struct conf ***confs)
{
	asfd_free(asfd);
	confs_free(confs);
	asfd_mock_teardown(&reads, &writes);
	alloc_check();
	fail_unless(recursive_delete(basepath)==0);
}

static void setup_bad_read(void)
{
	int r=0; int w=0;
	asfd_mock_write(&w, 0, CMD_GEN, "restore :");
	asfd_mock_read (&r, 0, CMD_GEN, "ok");
}

static void setup_no_files(void)
{
	int r=0; int w=0;
	asfd_mock_write(&w, 0, CMD_GEN, "restore :");
	asfd_mock_read (&r, 0, CMD_GEN, "ok");
	asfd_mock_read (&r, 0, CMD_GEN, "restoreend");
	asfd_mock_write(&w, 0, CMD_GEN, "restoreend_ok");
}

/*
static void setup_one_file(void)
{
	int r=0; int w=0;
	asfd_mock_write(&w, 0, CMD_GEN, "restore :");
	asfd_mock_read (&r, 0, CMD_GEN, "ok");
	asfd_mock_read (&r, 0, CMD_DATAPTH, "datapth");
	asfd_mock_read (&r, 0, CMD_ATTRIBS, "attribs");
	asfd_mock_read (&r, 0, CMD_FILE, basepath);
	asfd_mock_read (&r, 0, CMD_APPEND, "0123456789");
	asfd_mock_read (&w, 0, CMD_WARNING, "Unable to set file owner utest_restore: ERR=Operation not permitted\n");
	asfd_mock_read (&r, 0, CMD_ERROR, NULL);
}
*/

static struct conf **setup_conf(void)
{
	struct conf **confs=NULL;
	fail_unless((confs=confs_alloc())!=NULL);
	fail_unless(!confs_init(confs));
	return confs;
}

static void run_test(int expected_ret, void setup_callback(void))
{
	int result;
	struct asfd *asfd=asfd_mock_setup(&reads, &writes, 20, 20);
	struct conf **confs=setup_conf();
	const char *buf=MIN_CLIENT_CONF
		"protocol=1\n";

	fail_unless(recursive_delete(basepath)==0);

	fail_unless(!conf_load_global_only_buf(buf, confs));

	setup_callback();

	result=do_restore_client(asfd, confs,
		ACTION_RESTORE, 0 /* vss_restore */);
	fail_unless(result==expected_ret);

	tear_down(&asfd, &confs);
}

START_TEST(test_restore)
{
	run_test(-1, setup_bad_read);
	run_test( 0, setup_no_files);
	//run_test(-1, setup_one_file);
}
END_TEST

Suite *suite_client_restore(void)
{
	Suite *s;
	TCase *tc_core;

	s=suite_create("client_restore");

	tc_core=tcase_create("Core");

	tcase_add_test(tc_core, test_restore);
	suite_add_tcase(s, tc_core);

	return s;
}
