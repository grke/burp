#include "../test.h"
#include "../../src/action.h"
#include "../../src/alloc.h"
#include "../../src/asfd.h"
#include "../../src/cmd.h"
#include "../../src/cntr.h"
#include "../../src/iobuf.h"
#include "../../src/regexp.h"
#include "../../src/server/restore.h"
#include "../builders/build.h"
#include "../builders/build_asfd_mock.h"

static struct ioevent_list reads;
static struct ioevent_list writes;

static void tear_down(struct asfd **asfd, struct conf ***confs)
{
	asfd_free(asfd);
	asfd_mock_teardown(&reads, &writes);
	confs_free(confs);
	alloc_check();
}

// Tests that the client gets sent a suitable message when the server tried
// to restore on a bad regex.
static void setup_bad_regex(struct asfd *asfd)
{
	int w=0;
	asfd_mock_write(asfd, &w, 0, CMD_ERROR, "unable to compile regex: *\n");
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

	tear_down(&asfd, &confs);
}
END_TEST

Suite *suite_server_restore(void)
{
	Suite *s;
	TCase *tc_core;

	s=suite_create("server_restore");

	tc_core=tcase_create("Core");

	tcase_add_test(tc_core, test_send_regex_failure);
	suite_add_tcase(s, tc_core);

	return s;
}
