#include "../test.h"
#include "../../src/alloc.h"
#include "../../src/asfd.h"
#include "../../src/cmd.h"
#include "../../src/client/delete.h"
#include "../../src/iobuf.h"
#include "../builders/build_asfd_mock.h"

static struct ioevent_list reads;
static struct ioevent_list writes;

static void tear_down(struct asfd **asfd, struct conf ***confs)
{
	confs_free(confs);
	asfd_free(asfd);
	asfd_mock_teardown(&reads, &writes);
	alloc_check();
}

static void setup_write(struct asfd *asfd, const char *backup, int *w, int ret)
{
	char msg[64]="";
	snprintf(msg, sizeof(msg), "Delete %s", backup?backup:"");
	asfd_assert_write(asfd, w, ret, CMD_GEN, msg);
}

static void setup_all_ok(struct asfd *asfd, const char *backup)
{
	int r=0; int w=0;
	setup_write(asfd, backup, &w, 0);
	asfd_mock_read(asfd, &r, 0, CMD_GEN, "ok");
}

static void setup_write_fail(struct asfd *asfd, const char *backup)
{
	int w=0;
	setup_write(asfd, backup, &w, -1);
}

static void setup_read_fail(struct asfd *asfd, const char *backup)
{
	int r=0; int w=0;
	setup_write(asfd, backup, &w, 0);
	asfd_mock_read(asfd, &r, -1, CMD_GEN, "blah");
}

static void setup_not_deletable(struct asfd *asfd, const char *backup)
{
	int r=0; int w=0;
	setup_write(asfd, backup, &w, 0);
	asfd_mock_read(asfd, &r, 0, CMD_ERROR, "backup not deletable");
}

static void run_test(int expected_ret, const char *backup,
	void setup_callback(struct asfd *asfd, const char *backup))
{
	struct conf **confs;
	struct asfd *asfd;

	fail_unless((confs=confs_alloc())!=NULL);
	fail_unless(!confs_init(confs));
	set_string(confs[OPT_BACKUP], backup);

	asfd=asfd_mock_setup(&reads, &writes);
	setup_callback(asfd, backup);

	fail_unless(do_delete_client(asfd, confs)==expected_ret);
	tear_down(&asfd, &confs);
}

START_TEST(test_delete)
{
	run_test( 0, "2",  setup_all_ok);
	run_test( 0, NULL, setup_all_ok);
	run_test(-1, "4",  setup_write_fail);
	run_test(-1, "5",  setup_read_fail);
	run_test(-1, "10", setup_not_deletable);
}
END_TEST

Suite *suite_client_delete(void)
{
	Suite *s;
	TCase *tc_core;

	s=suite_create("client_delete");

	tc_core=tcase_create("Core");

	tcase_add_test(tc_core, test_delete);
	suite_add_tcase(s, tc_core);

	return s;
}
