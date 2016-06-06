#include "../test.h"
#include "../../src/asfd.h"
#include "../../src/async.h"
#include "../../src/conf.h"
#include "../../src/iobuf.h"
#include "../../src/sbuf.h"
#include "../../src/server/extra_comms.h"
#include "../builders/build.h"
#include "../builders/build_asfd_mock.h"

static struct ioevent_list reads;
static struct ioevent_list writes;

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
	struct conf ***confs, struct conf ***cconfs)
{
	if(as) *as=setup_async();
	if(confs) *confs=setup_conf();
	if(cconfs) *cconfs=setup_conf();
}

static void tear_down(struct async **as, struct asfd **asfd,
	struct conf ***confs, struct conf ***cconfs)
{
	async_free(as);
	asfd_free(asfd);
	asfd_mock_teardown(&reads, &writes);
	confs_free(confs);
	confs_free(cconfs);
	alloc_check();
}

static int async_rw_simple(struct async *as)
{
	return as->asfd->read(as->asfd);
}

static void run_test(int expected_ret,
	void setup_callback(struct asfd *asfd,
		struct conf **confs, struct conf **cconfs))
{
        struct async *as;
        struct asfd *asfd;
        struct conf **confs;
        struct conf **cconfs;
	char *incexc=NULL;
	int srestore=0;

        setup(&as, &confs, &cconfs);
        asfd=asfd_mock_setup(&reads, &writes);
	as->asfd_add(as, asfd);
	as->read_write=async_rw_simple;
	asfd->as=as;

	setup_callback(asfd, confs, cconfs);

	fail_unless(extra_comms(
		as,
		&incexc,
		&srestore,
		confs,
		cconfs
	)==expected_ret);

	tear_down(&as, &asfd, &confs, &cconfs);
}

static void setup_no_version(struct asfd *asfd,
	struct conf **confs, struct conf **cconfs)
{
}

static void setup_old_version(struct asfd *asfd,
	struct conf **confs, struct conf **cconfs)
{
	set_string(cconfs[OPT_PEER_VERSION], "1.2.0");
}

static void setup_unexpected_first_string(struct asfd *asfd,
	struct conf **confs, struct conf **cconfs)
{
	int r=0;
	set_string(cconfs[OPT_PEER_VERSION], "1.4.40");
	asfd_mock_read(asfd, &r, 0, CMD_GEN, "blah");
}

static void setup_1_3_0_write_problem(struct asfd *asfd,
	struct conf **confs, struct conf **cconfs)
{
	int r=0; int w=0;
	set_string(cconfs[OPT_PEER_VERSION], "1.3.0");
	asfd_mock_read(asfd, &r, 0, CMD_GEN, "extra_comms_begin");
	asfd_assert_write(asfd, &w, -1, CMD_GEN, "extra_comms_begin ok");
}

static void setup_send_features(struct asfd *asfd,
	struct conf **confs, struct conf **cconfs)
{
	int r=0; int w=0;
	set_string(cconfs[OPT_PEER_VERSION], VERSION);
	set_string(cconfs[OPT_DIRECTORY], "/var/spool/burp");
	set_string(cconfs[OPT_CNAME], "testclient");
	asfd_mock_read(asfd, &r, 0, CMD_GEN, "extra_comms_begin");
	asfd_assert_write(asfd, &w, -1, CMD_GEN, "extra_comms_begin ok:autoupgrade:incexc:orig_client:uname:msg:csetproto:rshash=blake2:");
}

START_TEST(test_extra_comms)
{
	run_test(0, setup_no_version);
	run_test(0, setup_old_version);
	run_test(-1, setup_unexpected_first_string);
	run_test(-1, setup_1_3_0_write_problem);
	run_test(-1, setup_send_features);
}
END_TEST

Suite *suite_server_extra_comms(void)
{
	Suite *s;
	TCase *tc_core;

	s=suite_create("server_extra_comms");

	tc_core=tcase_create("Core");
	tcase_set_timeout(tc_core, 60);

	tcase_add_test(tc_core, test_extra_comms);

	suite_add_tcase(s, tc_core);

	return s;
}
