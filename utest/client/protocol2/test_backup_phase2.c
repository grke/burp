#include "../../test.h"
#include "../../../src/alloc.h"
#include "../../../src/asfd.h"
#include "../../../src/async.h"
#include "../../../src/client/protocol2/backup_phase2.h"
#include "../../../src/iobuf.h"
#include "../../builders/build_asfd_mock.h"

static struct ioevent_list reads;
static struct ioevent_list writes;

static void tear_down(struct async **as)
{
	async_asfd_free_all(as);
	asfd_mock_teardown(&reads, &writes);
	alloc_check();
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

static void setup_phase2ok(void)
{
	int r=0; int w=0;
	asfd_mock_write(&w, 0, CMD_GEN, "backupphase2");
	asfd_mock_read (&r, 0, CMD_GEN, "ok");
}

static int mock_async_read_write_error(struct async *as)
{
	return -1;
}

static struct async *async_mock_setup(void)
{
	struct async *as;
	fail_unless((as=async_alloc())!=NULL);
	as->init(as, 0 /* estimate */);
	return as;
}

START_TEST(test_phase2_as_read_write_error)
{
	struct asfd *asfd;
	struct async *as;
	asfd=asfd_mock_setup(&reads, &writes, 10, 10);
	as=async_mock_setup();
	as->asfd_add(as, asfd);
	asfd->as=as;
	setup_phase2ok();
	as->read_write=mock_async_read_write_error;
	fail_unless(backup_phase2_client_protocol2(
		asfd,
		NULL, // confs
		0 // resume
	)==-1);
	tear_down(&as);
}
END_TEST

static void setup_phase2ok_then_cmd_error(void)
{
	int r=0; int w=0;
	asfd_mock_write(&w, 0, CMD_GEN, "backupphase2");
	asfd_mock_read (&r, 0, CMD_GEN, "ok");
	asfd_mock_read (&r, 0, CMD_ERROR, "some error");
}

static int mock_async_read(struct async *as)
{
	return as->asfd->read(as->asfd);
}

START_TEST(test_phase2_error_from_server)
{
	struct asfd *asfd;
	struct async *as;
	asfd=asfd_mock_setup(&reads, &writes, 10, 10);
	as=async_mock_setup();
	as->asfd_add(as, asfd);
	asfd->as=as;
	setup_phase2ok_then_cmd_error();
	as->read_write=mock_async_read;
	fail_unless(backup_phase2_client_protocol2(
		asfd,
		NULL, // confs
		0 // resume
	)==-1);
	tear_down(&as);
}
END_TEST

static void setup_phase2ok_file_request_missing_file(void)
{
	int r=0; int w=0;
	asfd_mock_write(&w, 0, CMD_GEN, "backupphase2");
	asfd_mock_read (&r, 0, CMD_GEN, "ok");
	asfd_mock_read (&r, 0, CMD_FILE, "some file");
	asfd_mock_write(&w, 0, CMD_WARNING, "some file has vanished\n");
}

START_TEST(test_phase2_file_request_missing)
{
	struct asfd *asfd;
	struct async *as;
	asfd=asfd_mock_setup(&reads, &writes, 10, 10);
	as=async_mock_setup();
	as->asfd_add(as, asfd);
	asfd->as=as;
	setup_phase2ok_file_request_missing_file();
	as->read_write=mock_async_read;

	// FIX THIS - a missing file should not cause a fatal error!
	fail_unless(backup_phase2_client_protocol2(
		asfd,
		NULL, // confs
		0 // resume
	)==-1);
	tear_down(&as);
}
END_TEST

Suite *suite_client_protocol2_backup_phase2(void)
{
	Suite *s;
	TCase *tc_core;

	s=suite_create("client_protocol2_backup_phase2");

	tc_core=tcase_create("Core");

	tcase_add_test(tc_core, test_phase2_no_asfd);
	tcase_add_test(tc_core, test_phase2_as_read_write_error);
	tcase_add_test(tc_core, test_phase2_error_from_server);
	tcase_add_test(tc_core, test_phase2_file_request_missing);
	suite_add_tcase(s, tc_core);

	return s;
}
