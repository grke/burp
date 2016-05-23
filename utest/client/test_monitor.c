#include "../test.h"
#include "../../src/alloc.h"
#include "../../src/asfd.h"
#include "../../src/async.h"
#include "../../src/iobuf.h"
#include "../../src/client/monitor.h"
#include "../builders/build_asfd_mock.h"

static struct ioevent_list areads;
static struct ioevent_list awrites;
static struct ioevent_list ireads;
static struct ioevent_list iwrites;
static struct ioevent_list oreads;
static struct ioevent_list owrites;

static struct async *setup(void)
{
	struct async *as;
	fail_unless((as=async_alloc())!=NULL);
	as->init(as, 0 /* estimate */);
	return as;
}

static void tear_down(struct async **as)
{
	async_free(as);
	alloc_check();
}

static void setup_in_error(struct asfd *sfd,
	struct asfd *in, struct asfd *out)
{
	int a=0;
	int r=0;
	asfd_mock_read_no_op(sfd, &a, 1);
	asfd_mock_read(in, &r, -1, CMD_GEN, "blah");
}

static void setup_input_to_sfd(struct asfd *sfd,
	struct asfd *in, struct asfd *out)
{
	int r=0;
	int ar=0;
	int aw=0;

	asfd_mock_read_no_op(sfd, &ar, 3);

	asfd_mock_read(in, &r, 0, CMD_GEN, "blah");
	asfd_mock_read(in, &r, 0, CMD_GEN, "halb");
	asfd_assert_write(sfd, &aw, 0, CMD_GEN, "blah");
	asfd_assert_write(sfd, &aw, 0, CMD_GEN, "halb");

	asfd_mock_read(in, &r, -1, CMD_GEN, "blah2");
}

static void setup_sfd_to_output(struct asfd *sfd,
	struct asfd *in, struct asfd *out)
{
	int a=0;
	int r=0;
	int w=0;

	asfd_mock_read_no_op(in, &r, 3);

	asfd_mock_read(sfd, &a, 0, CMD_GEN, "blah");
	asfd_mock_read(sfd, &a, 0, CMD_GEN, "halb");
	asfd_assert_write(out, &w, 0, CMD_GEN, "blah");
	asfd_assert_write(out, &w, 0, CMD_GEN, "halb");

	asfd_mock_read(sfd, &a, -1, CMD_GEN, "blah2");
}

static int async_rw_both(struct async *as)
{
	int ret=0;
	struct asfd *sfd=as->asfd;
	struct asfd *in=sfd->next;
	ret|=sfd->read(sfd);
	ret|=in->read(in);
	return ret;
}

static void run_test(int expected_ret,
	void setup_asfds_callback(struct asfd *sfd,
		struct asfd *in, struct asfd *out))
{
	struct async *as;
	struct asfd *sfd;
	struct asfd *in;
	struct asfd *out;

	as=setup();

	sfd=asfd_mock_setup(&areads, &awrites);
	in=asfd_mock_setup(&ireads, &iwrites);
	out=asfd_mock_setup(&oreads, &owrites);

	fail_unless((sfd->desc=strdup_w("main_socket", __func__))!=NULL);
	fail_unless((in->desc=strdup_w("stdin", __func__))!=NULL);
	fail_unless((out->desc=strdup_w("stdout", __func__))!=NULL);
	as->asfd_add(as, sfd);
	as->asfd_add(as, in);
	as->asfd_add(as, out);
	as->read_write=async_rw_both;

	setup_asfds_callback(sfd, in, out);

	fail_unless(monitor_client_main_loop(as)==expected_ret);

	asfd_free(&in);
	asfd_free(&out);
	asfd_free(&sfd);
	asfd_mock_teardown(&areads, &awrites);
	asfd_mock_teardown(&ireads, &iwrites);
	asfd_mock_teardown(&oreads, &owrites);
	tear_down(&as);
}

START_TEST(test_client_monitor_main_loop)
{
	run_test(-1, setup_in_error);
	run_test(-1, setup_input_to_sfd);
	run_test(-1, setup_sfd_to_output);
}
END_TEST

Suite *suite_client_monitor(void)
{
	Suite *s;
	TCase *tc_core;

	s=suite_create("client_monitor");

	tc_core=tcase_create("Core");
	tcase_set_timeout(tc_core, 60);

	tcase_add_test(tc_core, test_client_monitor_main_loop);

	suite_add_tcase(s, tc_core);

	return s;
}
