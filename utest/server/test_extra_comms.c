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
		struct conf **confs, struct conf **cconfs),
	void checks_callback(struct conf **confs, struct conf **cconfs))
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

	if(checks_callback)
		checks_callback(confs, cconfs);

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

static void setup_feature_write_problem(struct asfd *asfd,
	struct conf **confs, struct conf **cconfs)
{
	int r=0; int w=0;
	char rshash[32]="";
	char features[256]="";
	set_string(cconfs[OPT_PEER_VERSION], VERSION);
	set_string(cconfs[OPT_DIRECTORY], "/var/spool/burp");
	set_string(cconfs[OPT_CNAME], "testclient");
	set_protocol(cconfs, PROTO_AUTO);
	asfd_mock_read(asfd, &r, 0, CMD_GEN, "extra_comms_begin");
#ifndef RS_DEFAULT_STRONG_LEN
	snprintf(rshash, sizeof(rshash), "rshash=blake2:");
#endif
	snprintf(features, sizeof(features), "extra_comms_begin ok:autoupgrade:incexc:orig_client:uname:msg:csetproto:%s", rshash);
	asfd_assert_write(asfd, &w, -1, CMD_GEN, features);
}

static void setup_send_features_proto_begin(struct asfd *asfd,
	struct conf **confs, struct conf **cconfs, enum protocol protocol,
	int *r, int *w, const char *version)
{
	char proto[32]="";
	char rshash[32]="";
	char features[256]="";
	set_string(cconfs[OPT_PEER_VERSION], version);
	set_string(cconfs[OPT_DIRECTORY], "/var/spool/burp");
	set_string(cconfs[OPT_CNAME], "testclient");
	set_protocol(cconfs, protocol);
	asfd_mock_read(asfd, r, 0, CMD_GEN, "extra_comms_begin");
	if(protocol==PROTO_AUTO)
		snprintf(proto, sizeof(proto), "csetproto:");
	else
		snprintf(proto, sizeof(proto), "forceproto=%d:",
			int(protocol));
#ifndef RS_DEFAULT_STRONG_LEN
	snprintf(rshash, sizeof(rshash), "rshash=blake2:");
#endif
	snprintf(features, sizeof(features), "extra_comms_begin ok:autoupgrade:incexc:orig_client:uname:msg:%s%s", proto, rshash);
	asfd_assert_write(asfd, w, 0, CMD_GEN, features);
}

static void setup_send_features_proto_end(struct asfd *asfd, int *r, int *w)
{
	asfd_mock_read(asfd, r, 0, CMD_GEN, "extra_comms_end");
	asfd_assert_write(asfd, w, 0, CMD_GEN, "extra_comms_end ok");
}

static void setup_send_features_proto(struct asfd *asfd,
	struct conf **confs, struct conf **cconfs, enum protocol protocol,
	const char *version)
{
	int r=0; int w=0;
	setup_send_features_proto_begin(asfd, confs, cconfs, protocol, &r, &w,
		version);
	setup_send_features_proto_end(asfd, &r, &w);
}

static void setup_send_features_proto_auto(struct asfd *asfd,
	struct conf **confs, struct conf **cconfs)
{
	setup_send_features_proto(asfd, confs, cconfs, PROTO_AUTO, VERSION);
}

static void setup_send_features_proto_auto_old_client(struct asfd *asfd,
	struct conf **confs, struct conf **cconfs)
{
	setup_send_features_proto(asfd, confs, cconfs, PROTO_AUTO, "1.4.40");
}

static void setup_send_features_proto1(struct asfd *asfd,
	struct conf **confs, struct conf **cconfs)
{
	setup_send_features_proto(asfd, confs, cconfs, PROTO_1, VERSION);
}

static void setup_send_features_proto1_old_client(struct asfd *asfd,
	struct conf **confs, struct conf **cconfs)
{
	setup_send_features_proto(asfd, confs, cconfs, PROTO_1, "1.4.40");
}

static void setup_send_features_proto2(struct asfd *asfd,
	struct conf **confs, struct conf **cconfs)
{
	setup_send_features_proto(asfd, confs, cconfs, PROTO_2, VERSION);
}

static void setup_send_features_proto2_old_client(struct asfd *asfd,
	struct conf **confs, struct conf **cconfs)
{
	setup_send_features_proto(asfd, confs, cconfs, PROTO_2, "1.4.40");
}

static void setup_send_features_proto_auto_auto(struct asfd *asfd,
	struct conf **confs, struct conf **cconfs)
{
	int r=0; int w=0;
	setup_send_features_proto_begin(asfd, confs, cconfs,
		PROTO_AUTO, &r, &w, VERSION);
	asfd_mock_read(asfd, &r, 0, CMD_GEN, "protocol=0");
	asfd_assert_write(asfd, &w, 0, CMD_ERROR,
		"Client is trying to use protocol=0, which is unknown\n");
}

static void setup_send_features_proto_proto(struct asfd *asfd,
	struct conf **confs, struct conf **cconfs, const char *version,
	enum protocol protocol_server, enum protocol protocol_client)
{
	int r=0; int w=0;
	char cprotocol[16]="";
	snprintf(cprotocol, sizeof(cprotocol),
		"protocol=%d", (int)protocol_client);
	setup_send_features_proto_begin(asfd, confs, cconfs,
		protocol_server, &r, &w, version);
	asfd_mock_read(asfd, &r, 0, CMD_GEN, cprotocol);
	setup_send_features_proto_end(asfd, &r, &w);
}

static void setup_send_features_proto_auto_1(struct asfd *asfd,
	struct conf **confs, struct conf **cconfs)
{
	setup_send_features_proto_proto(asfd, confs, cconfs, VERSION,
		PROTO_AUTO, PROTO_1);
}

static void setup_send_features_proto_auto_1_old_client(struct asfd *asfd,
	struct conf **confs, struct conf **cconfs)
{
	setup_send_features_proto_proto(asfd, confs, cconfs, "1.4.40",
		PROTO_AUTO, PROTO_1);
}

static void setup_send_features_proto_auto_2(struct asfd *asfd,
	struct conf **confs, struct conf **cconfs)
{
	setup_send_features_proto_proto(asfd, confs, cconfs, VERSION,
		PROTO_AUTO, PROTO_2);
}

static void setup_send_features_proto_auto_2_old_client(struct asfd *asfd,
	struct conf **confs, struct conf **cconfs)
{
	setup_send_features_proto_proto(asfd, confs, cconfs, "1.4.40",
		PROTO_AUTO, PROTO_2);
}

static void setup_send_features_proto_x_y(struct asfd *asfd,
	struct conf **confs, struct conf **cconfs,
	enum protocol s_protocol, enum protocol c_protocol)
{
	int r=0; int w=0;
	char msg[256]="";
	char cliproto[16]="";
	snprintf(cliproto, sizeof(cliproto), "protocol=%d", (int)c_protocol);
	setup_send_features_proto_begin(asfd, confs, cconfs,
		s_protocol, &r, &w, VERSION);
	asfd_mock_read(asfd, &r, 0, CMD_GEN, cliproto);
	snprintf(msg, sizeof(msg), "Client is trying to use protocol=%d but server is set to protocol=%d\n", (int)c_protocol, (int)s_protocol);
	asfd_assert_write(asfd, &w, 0, CMD_ERROR, msg);
}

static void setup_send_features_proto_1_auto(struct asfd *asfd,
	struct conf **confs, struct conf **cconfs)
{
	setup_send_features_proto_x_y(asfd, confs, cconfs,
		PROTO_1, PROTO_AUTO);
}

static void setup_send_features_proto_2_auto(struct asfd *asfd,
	struct conf **confs, struct conf **cconfs)
{
	setup_send_features_proto_x_y(asfd, confs, cconfs,
		PROTO_2, PROTO_AUTO);
}

static void setup_send_features_proto_1_2(struct asfd *asfd,
	struct conf **confs, struct conf **cconfs)
{
	setup_send_features_proto_x_y(asfd, confs, cconfs,
		PROTO_1, PROTO_2);
}

static void setup_send_features_proto_2_1(struct asfd *asfd,
	struct conf **confs, struct conf **cconfs)
{
	setup_send_features_proto_x_y(asfd, confs, cconfs,
		PROTO_2, PROTO_1);
}

static void setup_send_features_proto_1_1(struct asfd *asfd,
	struct conf **confs, struct conf **cconfs)
{
	setup_send_features_proto_x_y(asfd, confs, cconfs,
		PROTO_1, PROTO_1);
}

static void setup_send_features_proto_2_2(struct asfd *asfd,
	struct conf **confs, struct conf **cconfs)
{
	setup_send_features_proto_x_y(asfd, confs, cconfs,
		PROTO_2, PROTO_2);
}

static void checks_proto_auto_no_features_from_client(
	struct conf **confs, struct conf **cconfs)
{
	// Server is PROTO_AUTO, client said nothing.
	fail_unless(get_protocol(confs)==PROTO_2);
}

static void checks_proto_auto_no_features_from_client_old_client(
	struct conf **confs, struct conf **cconfs)
{
	// Server is PROTO_AUTO, client said nothing. Client is old version,
	// so should be forced to PROTO_1.
	fail_unless(get_protocol(cconfs)==PROTO_1);
	fail_unless(get_protocol(confs)==PROTO_1);
}

static void checks_proto1_no_features_from_client(
	struct conf **confs, struct conf **cconfs)
{
	// Server is PROTO_1, client said nothing.
	fail_unless(get_protocol(confs)==PROTO_AUTO);
}

static void checks_proto1_no_features_from_client_old_client(
	struct conf **confs, struct conf **cconfs)
{
	// Server is PROTO_1, client said nothing. Client is old version.
	fail_unless(get_protocol(confs)==PROTO_AUTO);
}

static void checks_proto2_no_features_from_client(
	struct conf **confs, struct conf **cconfs)
{
	// Server is PROTO_2, client said nothing.
	fail_unless(get_protocol(confs)==PROTO_AUTO);
}

static void checks_proto_auto_1(
	struct conf **confs, struct conf **cconfs)
{
	// Server is PROTO_AUTO, client said PROTO_1
	fail_unless(get_protocol(confs)==PROTO_1);
	// We did not set OPT_RSHASH. It should be set to RSHASH_MD4 for us.
	fail_unless(get_e_rshash(confs[OPT_RSHASH])==RSHASH_MD4);
	fail_unless(get_e_rshash(cconfs[OPT_RSHASH])==RSHASH_MD4);
}

static void checks_proto_auto_2(
	struct conf **confs, struct conf **cconfs)
{
	// Server is PROTO_AUTO, client said PROTO_2
	fail_unless(get_protocol(confs)==PROTO_2);
}

static void setup_unexpected_cmd_feature(struct asfd *asfd,
	struct conf **confs, struct conf **cconfs)
{
	int r=0; int w=0;
	setup_send_features_proto_begin(asfd, confs, cconfs,
		PROTO_AUTO, &r, &w, VERSION);
	asfd_mock_read(asfd, &r, 0, CMD_FILE, "blah");
}

static void setup_autoupgrade_no_os(struct asfd *asfd,
	struct conf **confs, struct conf **cconfs)
{
	int r=0; int w=0;
	setup_send_features_proto_begin(asfd, confs, cconfs,
		PROTO_AUTO, &r, &w, VERSION);
	asfd_mock_read(asfd, &r, 0, CMD_GEN, "autoupgrade:");
	setup_send_features_proto_end(asfd, &r, &w);
}

static void setup_autoupgrade(struct asfd *asfd,
	struct conf **confs, struct conf **cconfs)
{
	int r=0; int w=0;
	setup_send_features_proto_begin(asfd, confs, cconfs,
		PROTO_AUTO, &r, &w, VERSION);
	asfd_mock_read(asfd, &r, 0, CMD_GEN, "autoupgrade:some_os");
	// Server does not have an autoupgrade_dir set.
	asfd_assert_write(asfd, &w, 0, CMD_GEN, "do not autoupgrade");
	setup_send_features_proto_end(asfd, &r, &w);
}

START_TEST(test_extra_comms)
{
	run_test(0, setup_no_version, NULL);
	run_test(0, setup_old_version, NULL);
	run_test(-1, setup_unexpected_first_string, NULL);
	run_test(-1, setup_1_3_0_write_problem, NULL);
	run_test(-1, setup_feature_write_problem, NULL);

	run_test(0, setup_send_features_proto_auto,
		checks_proto_auto_no_features_from_client);
	run_test(0, setup_send_features_proto1,
		checks_proto1_no_features_from_client);
	run_test(0, setup_send_features_proto2,
		checks_proto2_no_features_from_client);
	run_test(0, setup_send_features_proto_auto_1,
		checks_proto_auto_1);
	run_test(0, setup_send_features_proto_auto_2,
		checks_proto_auto_2);

	run_test(0, setup_send_features_proto_auto_old_client,
		checks_proto_auto_no_features_from_client_old_client);
	run_test(0, setup_send_features_proto1_old_client,
		checks_proto1_no_features_from_client_old_client);
	run_test(-1, setup_send_features_proto2_old_client,
		NULL);
	run_test(0, setup_send_features_proto_auto_1_old_client,
		checks_proto_auto_1);
	run_test(-1, setup_send_features_proto_auto_2_old_client,
		NULL);

	run_test(-1, setup_send_features_proto_auto_auto,
		NULL);
	run_test(-1, setup_send_features_proto_1_auto,
		NULL);
	run_test(-1, setup_send_features_proto_2_auto,
		NULL);
	run_test(-1, setup_send_features_proto_1_2,
		NULL);
	run_test(-1, setup_send_features_proto_2_1,
		NULL);
	run_test(-1, setup_send_features_proto_1_1,
		NULL);
	run_test(-1, setup_send_features_proto_2_2,
		NULL);

	run_test(-1, setup_unexpected_cmd_feature,
		NULL);

	run_test(0, setup_autoupgrade_no_os,
		NULL);
	run_test(0, setup_autoupgrade,
		NULL);
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
