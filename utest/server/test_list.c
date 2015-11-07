#include "../test.h"
#include "../../src/alloc.h"
#include "../../src/asfd.h"
#include "../../src/bu.h"
#include "../../src/fsops.h"
#include "../../src/server/bu_get.h"
#include "../../src/server/list.h"
#include "../../src/server/sdirs.h"
#include "../../src/iobuf.h"
#include "../builders/build.h"
#include "../builders/build_asfd_mock.h"

#define BASE	"utest_server_list"

static struct ioevent_list reads;
static struct ioevent_list writes;

static void tear_down(struct asfd **asfd, struct sdirs **sdirs)
{
	asfd_free(asfd);
	asfd_mock_teardown(&reads, &writes);
	sdirs_free(sdirs);
	fail_unless(recursive_delete(BASE)==0);
	alloc_check();
}

static struct sdirs *setup_sdirs(struct sd *s, int slen, enum protocol protocol)
{
	struct sdirs *sdirs;
	fail_unless(recursive_delete(BASE)==0);
	fail_unless((sdirs=sdirs_alloc())!=NULL);
	fail_unless(!sdirs_init(sdirs, protocol,
		BASE, // directory
		"utestclient", // cname
		NULL, // client_lockdir
		"a_group", // dedup_group
		NULL // manual_delete
		));
	build_storage_dirs(sdirs, s, slen);
	return sdirs;
}

static struct sd sd1[] = {
	{ "0000001 1970-01-01 00:00:00", 1, 1, BU_CURRENT|BU_DELETABLE }
};

static struct sd sd2[] = {
	{ "0000001 1970-01-01 00:00:00", 1, 1, BU_CURRENT|BU_DELETABLE },
	{ "0000002 1970-01-02 00:00:00", 2, 2, 0 },
	{ "0000003 1970-01-03 00:00:00", 3, 3, 0 }
};

static void setup_asfd_bu_failure(void)
{
}

static void setup_asfd_1(void)
{
	int w=0;
	asfd_mock_write(&w, 0,
		CMD_TIMESTAMP, "0000001 1970-01-01 00:00:00 (deletable)");
}

static void setup_asfd_1_protocol2(void)
{
	int w=0;
	asfd_mock_write(&w, 0,
		CMD_TIMESTAMP, "0000001 1970-01-01 00:00:00");
}

static void setup_asfd_2(void)
{
	int w=0;
	asfd_mock_write(&w, 0,
		CMD_TIMESTAMP, "0000001 1970-01-01 00:00:00 (deletable)");
	asfd_mock_write(&w, 0,
		CMD_TIMESTAMP, "0000002 1970-01-02 00:00:00");
	asfd_mock_write(&w, 0,
		CMD_TIMESTAMP, "0000003 1970-01-03 00:00:00");
}

static void setup_asfd_2_protocol2(void)
{
	int w=0;
	asfd_mock_write(&w, 0,
		CMD_TIMESTAMP, "0000001 1970-01-01 00:00:00");
	asfd_mock_write(&w, 0,
		CMD_TIMESTAMP, "0000002 1970-01-02 00:00:00");
	asfd_mock_write(&w, 0,
		CMD_TIMESTAMP, "0000003 1970-01-03 00:00:00");
}

static void run_test(int expected_ret, enum protocol protocol,
	struct sd *s, int slen,
	void setup_callback(void))
{
	struct asfd *asfd;
	struct sdirs *sdirs=NULL;
	if(slen) sdirs=setup_sdirs(s, slen, protocol);

	asfd=asfd_mock_setup(&reads, &writes, 10, 10);

	setup_callback();

	fail_unless(do_list_server(asfd, sdirs, NULL, protocol,
		NULL, NULL, NULL)==expected_ret);
	tear_down(&asfd, &sdirs);
}

START_TEST(test_server_list)
{
	run_test( -1, PROTO_1, NULL, 0,            setup_asfd_bu_failure);
	run_test( -1, PROTO_2, NULL, 0,            setup_asfd_bu_failure);
	run_test(  0, PROTO_1, sd1,  ARR_LEN(sd1), setup_asfd_1);
	run_test(  0, PROTO_1, sd2,  ARR_LEN(sd2), setup_asfd_2);
	run_test(  0, PROTO_2, sd1,  ARR_LEN(sd1), setup_asfd_1_protocol2);
	run_test(  0, PROTO_2, sd2,  ARR_LEN(sd2), setup_asfd_2_protocol2);
}
END_TEST

Suite *suite_server_list(void)
{
	Suite *s;
	TCase *tc_core;

	s=suite_create("server_list");

	tc_core=tcase_create("Core");

	tcase_add_test(tc_core, test_server_list);
	suite_add_tcase(s, tc_core);

	return s;
}
