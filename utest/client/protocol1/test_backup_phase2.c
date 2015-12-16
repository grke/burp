#include "../../test.h"
#include "../../../src/asfd.h"
#include "../../../src/client/protocol1/backup_phase2.h"
#include "../../../src/iobuf.h"
#include "../../builders/build_asfd_mock.h"

static struct ioevent_list reads;
static struct ioevent_list writes;

static void tear_down(struct asfd **asfd)
{
	asfd_free(asfd);
	asfd_mock_teardown(&reads, &writes);
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
	asfd_mock_write(asfd, &w, 0, CMD_GEN, "backupphase2");
	asfd_mock_read (asfd, &r, 0, CMD_GEN, "ok");
	asfd_mock_read (asfd, &r, -1, CMD_GEN, "blah");
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
	tear_down(&asfd);
}
END_TEST

static void setup_phase2_empty_backup_ok(struct asfd *asfd)
{
	int r=0; int w=0;
	asfd_mock_write(asfd, &w, 0, CMD_GEN, "backupphase2");
	asfd_mock_read (asfd, &r, 0, CMD_GEN, "ok");
	asfd_mock_read (asfd, &r, 0, CMD_GEN, "backupphase2end");
	asfd_mock_write(asfd, &w, 0, CMD_GEN, "okbackupphase2end");
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
	tear_down(&asfd);
}
END_TEST

static void setup_phase2_empty_backup_ok_with_warning(struct asfd *asfd)
{
	int r=0; int w=0;
	asfd_mock_write(asfd, &w, 0, CMD_GEN, "backupphase2");
	asfd_mock_read (asfd, &r, 0, CMD_GEN, "ok");
	asfd_mock_read (asfd, &r, 0, CMD_WARNING, "some warning");
	asfd_mock_read (asfd, &r, 0, CMD_GEN, "backupphase2end");
	asfd_mock_write(asfd, &w, 0, CMD_GEN, "okbackupphase2end");
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
	tear_down(&asfd);
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
	suite_add_tcase(s, tc_core);

	return s;
}
