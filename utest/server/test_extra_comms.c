#include "../test.h"
#include "../../src/alloc.h"
#include "../../src/asfd.h"
#include "../../src/async.h"
#include "../../src/conf.h"
#include "../../src/fsops.h"
#include "../../src/iobuf.h"
#include "../../src/sbuf.h"
#include "../../src/server/extra_comms.h"
#include "../../src/strlist.h"
#include "../builders/build.h"
#include "../builders/build_file.h"
#include "../builders/build_asfd_mock.h"

#define BASE			"utest_server_extra_comms"
#define TESTCLIENT		"testclient"
#define SPOOL			BASE "/spool"
#define SRESTORE_FILE		SPOOL "/testclient/restore"
#define SRESTORE_FILE_CLI2	SPOOL "/cli2/restore"

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

static void clean(void)
{
	fail_unless(!recursive_delete(BASE));
	fail_unless(!recursive_delete(CLIENTCONFDIR));
}

static void setup(struct async **as,
	struct conf ***confs, struct conf ***cconfs)
{
	clean();
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
	clean();
	alloc_check();
}

static int async_rw_simple(struct async *as)
{
	return as->asfd->read(as->asfd);
}

static void run_test(int expected_ret,
	void setup_callback(struct asfd *asfd,
		struct conf **confs, struct conf **cconfs),
	void checks_callback(struct conf **confs, struct conf **cconfs,
		const char *incexc, int srestore))
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
		checks_callback(confs, cconfs, incexc, srestore);

	free_w(&incexc);
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

static void common_confs(struct conf **cconfs, const char *version,
	enum protocol protocol)
{
	set_string(cconfs[OPT_PEER_VERSION], version);
	set_string(cconfs[OPT_DIRECTORY], BASE "/spool");
	set_string(cconfs[OPT_CNAME], TESTCLIENT);
	set_string(cconfs[OPT_DEDUP_GROUP], "global");
	set_protocol(cconfs, protocol);
}

static const char *get_features(enum protocol protocol, int srestore,
	const char *version)
{
	char proto[32]="";
	char rshash[32]="";
	int old_version=0;
	static char features[256]="";

#ifdef HAVE_BLAKE2
	snprintf(rshash, sizeof(rshash), "rshash=blake2:");
#endif
	if(protocol==PROTO_AUTO)
		snprintf(proto, sizeof(proto), "csetproto:");
	else
		snprintf(proto, sizeof(proto), "forceproto=%d:",
			(int)protocol);

	if(version && !strcmp(version, "1.4.40"))
		old_version=1;

	snprintf(features, sizeof(features), "extra_comms_begin ok:autoupgrade:incexc:orig_client:uname:failover:vss_restore:regex_icase:%s%smsg:%s%sseed:", srestore?"srestore:":"", old_version?"":"counters_json:", proto, rshash);
	return features;
}

static void setup_feature_write_problem(struct asfd *asfd,
	struct conf **confs, struct conf **cconfs)
{
	int r=0; int w=0;
	const char *features;
	enum protocol protocol=PROTO_AUTO;
	common_confs(cconfs, PACKAGE_VERSION, protocol);
	asfd_mock_read(asfd, &r, 0, CMD_GEN, "extra_comms_begin");
	features=get_features(protocol, /*srestore*/0, NULL/*version*/);
	asfd_assert_write(asfd, &w, -1, CMD_GEN, features);
}

static void setup_send_features_proto_begin(struct asfd *asfd,
	struct conf **confs, struct conf **cconfs, enum protocol protocol,
	int *r, int *w, const char *version, int srestore)
{
	const char *features=NULL;
	common_confs(cconfs, version, protocol);
	asfd_mock_read(asfd, r, 0, CMD_GEN, "extra_comms_begin");
	features=get_features(protocol, srestore, version);
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
		version, /*srestore*/0);
	setup_send_features_proto_end(asfd, &r, &w);
}

static void setup_send_features_proto_auto(struct asfd *asfd,
	struct conf **confs, struct conf **cconfs)
{
	setup_send_features_proto(asfd, confs, cconfs, PROTO_AUTO, PACKAGE_VERSION);
}

static void setup_send_features_proto_auto_old_client(struct asfd *asfd,
	struct conf **confs, struct conf **cconfs)
{
	setup_send_features_proto(asfd, confs, cconfs, PROTO_AUTO, "1.4.40");
}

static void setup_send_features_proto1(struct asfd *asfd,
	struct conf **confs, struct conf **cconfs)
{
	setup_send_features_proto(asfd, confs, cconfs, PROTO_1, PACKAGE_VERSION);
}

static void setup_send_features_proto1_old_client(struct asfd *asfd,
	struct conf **confs, struct conf **cconfs)
{
	setup_send_features_proto(asfd, confs, cconfs, PROTO_1, "1.4.40");
}

static void setup_send_features_proto2(struct asfd *asfd,
	struct conf **confs, struct conf **cconfs)
{
	setup_send_features_proto(asfd, confs, cconfs, PROTO_2, PACKAGE_VERSION);
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
		PROTO_AUTO, &r, &w, PACKAGE_VERSION, /*srestore*/0);
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
		protocol_server, &r, &w, version, /*srestore*/0);
	asfd_mock_read(asfd, &r, 0, CMD_GEN, cprotocol);
	setup_send_features_proto_end(asfd, &r, &w);
}

static void setup_send_features_proto_auto_1(struct asfd *asfd,
	struct conf **confs, struct conf **cconfs)
{
	setup_send_features_proto_proto(asfd, confs, cconfs, PACKAGE_VERSION,
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
	setup_send_features_proto_proto(asfd, confs, cconfs, PACKAGE_VERSION,
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
		s_protocol, &r, &w, PACKAGE_VERSION, /*srestore*/0);
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
	setup_send_features_proto_proto(asfd, confs, cconfs, PACKAGE_VERSION,
		PROTO_1, PROTO_1);
}

static void setup_send_features_proto_2_2(struct asfd *asfd,
	struct conf **confs, struct conf **cconfs)
{
	setup_send_features_proto_proto(asfd, confs, cconfs, PACKAGE_VERSION,
		PROTO_2, PROTO_2);
}

static void checks_proto_auto_no_features_from_client(
	struct conf **confs, struct conf **cconfs, const char *incexc,
	int srestore)
{
	// Server is PROTO_AUTO, client said nothing.
	fail_unless(get_protocol(confs)==PROTO_1);
}

static void checks_proto_auto_no_features_from_client_old_client(
	struct conf **confs, struct conf **cconfs, const char *incexc,
	int srestore)
{
	// Server is PROTO_AUTO, client said nothing. Client is old version,
	// so should be forced to PROTO_1.
	fail_unless(get_protocol(cconfs)==PROTO_1);
	fail_unless(get_protocol(confs)==PROTO_1);
}

static void checks_proto1_no_features_from_client(
	struct conf **confs, struct conf **cconfs, const char *incexc,
	int srestore)
{
	// Server is PROTO_1, client said nothing.
	fail_unless(get_protocol(confs)==PROTO_AUTO);
}

static void checks_proto1_no_features_from_client_old_client(
	struct conf **confs, struct conf **cconfs, const char *incexc,
	int srestore)
{
	// Server is PROTO_1, client said nothing. Client is old version.
	fail_unless(get_protocol(confs)==PROTO_AUTO);
}

static void checks_proto2_no_features_from_client(
	struct conf **confs, struct conf **cconfs, const char *incexc,
	int srestore)
{
	// Server is PROTO_2, client said nothing.
	fail_unless(get_protocol(confs)==PROTO_AUTO);
}

static void checks_proto_auto_1(
	struct conf **confs, struct conf **cconfs, const char *incexc,
	int srestore)
{
	// Server is PROTO_AUTO, client said PROTO_1
	fail_unless(get_protocol(confs)==PROTO_1);
	// We did not set OPT_RSHASH. It should be set to RSHASH_MD4 for us.
	fail_unless(get_e_rshash(confs[OPT_RSHASH])==RSHASH_MD4);
	fail_unless(get_e_rshash(cconfs[OPT_RSHASH])==RSHASH_MD4);
}

static void checks_proto_auto_2(
	struct conf **confs, struct conf **cconfs, const char *incexc,
	int srestore)
{
	// Server is PROTO_AUTO, client said PROTO_2
	fail_unless(get_protocol(confs)==PROTO_2);
}

static void setup_unexpected_cmd_feature(struct asfd *asfd,
	struct conf **confs, struct conf **cconfs)
{
	int r=0; int w=0;
	setup_send_features_proto_begin(asfd, confs, cconfs,
		PROTO_AUTO, &r, &w, PACKAGE_VERSION, /*srestore*/0);
	asfd_mock_read(asfd, &r, 0, CMD_FILE, "blah");
}

static void setup_simple(struct asfd *asfd,
	struct conf **confs, struct conf **cconfs, const char *feature,
	int srestore)
{
	int r=0; int w=0;
	setup_send_features_proto_begin(asfd, confs, cconfs,
		PROTO_AUTO, &r, &w, PACKAGE_VERSION, srestore);
	asfd_mock_read(asfd, &r, 0, CMD_GEN, feature);
	setup_send_features_proto_end(asfd, &r, &w);
}

static void setup_autoupgrade_no_os(struct asfd *asfd,
	struct conf **confs, struct conf **cconfs)
{
	setup_simple(asfd, confs, cconfs, "autoupgrade:", /*srestore*/0);
}

static void setup_autoupgrade(struct asfd *asfd,
	struct conf **confs, struct conf **cconfs)
{
	int r=0; int w=0;
	setup_send_features_proto_begin(asfd, confs, cconfs,
		PROTO_AUTO, &r, &w, PACKAGE_VERSION, /*srestore*/0);
	asfd_mock_read(asfd, &r, 0, CMD_GEN, "autoupgrade:some_os");
	// Server does not have an autoupgrade_dir set.
	asfd_assert_write(asfd, &w, 0, CMD_GEN, "do not autoupgrade");
	setup_send_features_proto_end(asfd, &r, &w);
}

static void setup_rshash_blake2(struct asfd *asfd,
	struct conf **confs, struct conf **cconfs)
{
#ifdef HAVE_BLAKE2
	setup_simple(asfd, confs, cconfs, "rshash=blake2", /*srestore*/0);
#else
	int r=0; int w=0;
	setup_send_features_proto_begin(asfd, confs, cconfs,
		PROTO_AUTO, &r, &w, PACKAGE_VERSION, /*srestore*/0);
	asfd_mock_read(asfd, &r, 0, CMD_GEN, "rshash=blake2");
#endif
}

static void checks_rshash_blake2(struct conf **confs, struct conf **cconfs,
	const char *incexc, int srestore)
{
#ifdef HAVE_BLAKE2
	fail_unless(get_e_rshash(confs[OPT_RSHASH])==RSHASH_BLAKE2);
	fail_unless(get_e_rshash(cconfs[OPT_RSHASH])==RSHASH_BLAKE2);
#else
	fail_unless(get_e_rshash(confs[OPT_RSHASH])==RSHASH_UNSET);
	fail_unless(get_e_rshash(cconfs[OPT_RSHASH])==RSHASH_UNSET);
#endif
}

static void setup_msg(struct asfd *asfd,
	struct conf **confs, struct conf **cconfs)
{
	setup_simple(asfd, confs, cconfs, "msg", /*srestore*/0);
}

static void checks_msg(struct conf **confs, struct conf **cconfs,
	const char *incexc, int srestore)
{
	fail_unless(get_int(confs[OPT_MESSAGE])==1);
	fail_unless(get_int(cconfs[OPT_MESSAGE])==1);
}

static void setup_counters_ok(struct asfd *asfd,
	struct conf **confs, struct conf **cconfs)
{
	setup_simple(asfd, confs, cconfs, "counters_json ok", /*srestore*/0);
}

static void checks_counters_ok(struct conf **confs, struct conf **cconfs,
	const char *incexc, int srestore)
{
	fail_unless(get_int(cconfs[OPT_SEND_CLIENT_CNTR])==1);
}

static void setup_uname(struct asfd *asfd,
	struct conf **confs, struct conf **cconfs)
{
	setup_simple(asfd, confs, cconfs, "uname=some_os", /*srestore*/0);
}

static void checks_uname(struct conf **confs, struct conf **cconfs,
	const char *incexc, int srestore)
{
	fail_unless(get_int(cconfs[OPT_CLIENT_IS_WINDOWS])==0);
}

static void setup_uname_is_windows(struct asfd *asfd,
	struct conf **confs, struct conf **cconfs)
{
	setup_simple(asfd, confs, cconfs, "uname=Windows", /*srestore*/0);
}

static void checks_uname_is_windows(struct conf **confs, struct conf **cconfs,
	const char *incexc, int srestore)
{
	fail_unless(get_int(cconfs[OPT_CLIENT_IS_WINDOWS])==1);
}

static void setup_unexpected_feature(struct asfd *asfd,
	struct conf **confs, struct conf **cconfs)
{
	int r=0; int w=0;
	setup_send_features_proto_begin(asfd, confs, cconfs,
		PROTO_AUTO, &r, &w, PACKAGE_VERSION, /*srestore*/0);
	asfd_mock_read(asfd, &r, 0, CMD_GEN, "somenonsense");
}

static void setup_srestore_not_ok(struct asfd *asfd,
	struct conf **confs, struct conf **cconfs)
{
	build_file(SRESTORE_FILE, "");
	setup_simple(asfd, confs, cconfs, "srestore not ok", /*srestore*/1);
}

static void checks_srestore_not_ok(struct conf **confs, struct conf **cconfs,
	const char *incexc, int srestore)
{
	struct stat statp;
	// Should have deleted the restore file.
	fail_unless(lstat(SRESTORE_FILE, &statp));
	fail_unless(get_string(cconfs[OPT_RESTORE_PATH])==NULL);
}

static void setup_srestore(struct asfd *asfd,
	struct conf **confs, struct conf **cconfs, int *r, int *w)
{
	struct strlist *strlist=NULL;
	build_file(SRESTORE_FILE, "");
	setup_send_features_proto_begin(asfd, confs, cconfs, PROTO_AUTO,
		r, w, PACKAGE_VERSION, /*srestore*/1);

	strlist_add(&strlist, "/some/path", 1);
	// This needs to get unset.
	set_strlist(cconfs[OPT_INCEXCDIR], strlist);

	asfd_mock_read(asfd, r, 0, CMD_GEN, "srestore ok");
	asfd_assert_write(asfd, w, 0, CMD_GEN, "overwrite = 0");
	asfd_assert_write(asfd, w, 0, CMD_GEN, "strip = 0");
	asfd_assert_write(asfd, w, 0, CMD_GEN, "regex_case_insensitive = 0");
	asfd_assert_write(asfd, w, 0, CMD_GEN, "srestore end");
}

static void setup_srestore_ok(struct asfd *asfd,
	struct conf **confs, struct conf **cconfs)
{
	int r=0; int w=0;
	setup_srestore(asfd, confs, cconfs, &r, &w);
	asfd_mock_read(asfd, &r, 0, CMD_GEN, "srestore end ok");
	setup_send_features_proto_end(asfd, &r, &w);
}

static void checks_srestore_ok(struct conf **confs, struct conf **cconfs,
	const char *incexc, int srestore)
{
	struct stat statp;
	// Should not have deleted the restore file.
	fail_unless(!lstat(SRESTORE_FILE, &statp));
	fail_unless(!strcmp(get_string(cconfs[OPT_RESTORE_PATH]),
		SRESTORE_FILE));
	fail_unless(srestore==1);
	fail_unless(get_strlist(cconfs[OPT_INCEXCDIR])==NULL);
}

static void setup_srestore_ok_error(struct asfd *asfd,
	struct conf **confs, struct conf **cconfs)
{
	int r=0; int w=0;
	setup_srestore(asfd, confs, cconfs, &r, &w);
	asfd_mock_read(asfd, &r, -1, CMD_GEN, "srestore end ok");
}

static void setup_sincexc_ok(struct asfd *asfd,
	struct conf **confs, struct conf **cconfs)
{
	int r=0; int w=0;
	setup_send_features_proto_begin(asfd, confs, cconfs, PROTO_AUTO,
		&r, &w, PACKAGE_VERSION, /*srestore*/0);
	asfd_mock_read(asfd, &r, 0, CMD_GEN, "sincexc ok");
	asfd_assert_write(asfd, &w, 0, CMD_GEN, "cross_all_filesystems = 0");
	asfd_assert_write(asfd, &w, 0, CMD_GEN, "read_all_fifos = 0");
	asfd_assert_write(asfd, &w, 0, CMD_GEN, "read_all_blockdevs = 0");
	asfd_assert_write(asfd, &w, 0, CMD_GEN, "min_file_size = 0");
	asfd_assert_write(asfd, &w, 0, CMD_GEN, "max_file_size = 0");
	asfd_assert_write(asfd, &w, 0, CMD_GEN, "split_vss = 0");
	asfd_assert_write(asfd, &w, 0, CMD_GEN, "strip_vss = 0");
	asfd_assert_write(asfd, &w, 0, CMD_GEN, "acl = 1");
	asfd_assert_write(asfd, &w, 0, CMD_GEN, "xattr = 1");
	asfd_assert_write(asfd, &w, 0, CMD_GEN, "atime = 0");
	asfd_assert_write(asfd, &w, 0,
		CMD_GEN, "scan_problem_raises_error = 0");
	asfd_assert_write(asfd, &w, 0, CMD_GEN, "overwrite = 0");
	asfd_assert_write(asfd, &w, 0, CMD_GEN, "strip = 0");
	asfd_assert_write(asfd, &w, 0, CMD_GEN, "regex_case_insensitive = 0");
	asfd_assert_write(asfd, &w, 0, CMD_GEN, "sincexc end");
	asfd_mock_read(asfd, &r, 0, CMD_GEN, "sincexc end ok");
	setup_send_features_proto_end(asfd, &r, &w);
}

static void setup_incexc(struct asfd *asfd,
	struct conf **confs, struct conf **cconfs)
{
	int r=0; int w=0;
	setup_send_features_proto_begin(asfd, confs, cconfs, PROTO_AUTO,
		&r, &w, PACKAGE_VERSION, /*srestore*/0);
	asfd_mock_read(asfd, &r, 0, CMD_GEN, "incexc");
	asfd_assert_write(asfd, &w, 0, CMD_GEN, "incexc ok");
	asfd_mock_read(asfd, &r, 0, CMD_GEN, "include = /some/path");
	asfd_mock_read(asfd, &r, 0, CMD_GEN, "incexc end");
	asfd_assert_write(asfd, &w, 0, CMD_GEN, "incexc end ok");
	setup_send_features_proto_end(asfd, &r, &w);
}

static void checks_incexc(struct conf **confs, struct conf **cconfs,
	const char *incexc, int srestore)
{
	fail_unless(!strcmp(incexc,
		"include = /some/path\n\ncompression = 9\n"));
}

static void setup_orig_client_not_existing(struct asfd *asfd,
	struct conf **confs, struct conf **cconfs)
{
	int r=0; int w=0;

	setup_send_features_proto_begin(asfd, confs, cconfs,
		PROTO_AUTO, &r, &w, PACKAGE_VERSION, /*srestore*/0);
	asfd_mock_read(asfd, &r, 0, CMD_GEN, "orig_client=cli2");
}

static void setup_orig_client(struct asfd *asfd,
	struct conf **confs, struct conf **cconfs)
{
	int r=0; int w=0;
	enum protocol protocol=PROTO_AUTO;

	common_confs(cconfs, PACKAGE_VERSION, protocol);
	set_string(confs[OPT_CLIENTCONFDIR], CLIENTCONFDIR);
	build_file(CLIENTCONFDIR "/cli2", "restore_client=" TESTCLIENT);
	setup_send_features_proto_begin(asfd, confs, cconfs,
		protocol, &r, &w, PACKAGE_VERSION, /*srestore*/0);
	asfd_mock_read(asfd, &r, 0, CMD_GEN, "orig_client=cli2");
	asfd_assert_write(asfd, &w, 0, CMD_GEN, "orig_client ok");
	setup_send_features_proto_end(asfd, &r, &w);
}

static void checks_orig_client(struct conf **confs, struct conf **cconfs,
	const char *incexc, int srestore)
{
	const char *orig_client;
	const char *restore_client;
	fail_unless(!strcmp(get_string(cconfs[OPT_CNAME]), "cli2"));
	restore_client=get_string(cconfs[OPT_SUPER_CLIENT]);
	orig_client=get_string(cconfs[OPT_ORIG_CLIENT]);
	fail_unless(!strcmp(orig_client, restore_client));
}

static void setup_orig_client_srestore(struct asfd *asfd,
	struct conf **confs, struct conf **cconfs)
{
	int r=0; int w=0;
	enum protocol protocol=PROTO_AUTO;
	build_file(SRESTORE_FILE, "overwrite=1");
	build_file(SRESTORE_FILE_CLI2, "strip=1");

	common_confs(cconfs, PACKAGE_VERSION, protocol);
	set_string(confs[OPT_CLIENTCONFDIR], CLIENTCONFDIR);
	build_file(CLIENTCONFDIR "/cli2", "restore_client=" TESTCLIENT);
	setup_send_features_proto_begin(asfd, confs, cconfs,
		protocol, &r, &w, PACKAGE_VERSION, /*srestore*/1);

	asfd_mock_read(asfd, &r, 0, CMD_GEN, "srestore ok");
	asfd_assert_write(asfd, &w, 0, CMD_GEN, "overwrite = 1");
	asfd_assert_write(asfd, &w, 0, CMD_GEN, "strip = 0");
	asfd_assert_write(asfd, &w, 0, CMD_GEN, "regex_case_insensitive = 0");
	asfd_assert_write(asfd, &w, 0, CMD_GEN, "srestore end");
	asfd_mock_read(asfd, &r, 0, CMD_GEN, "srestore end ok");

	asfd_mock_read(asfd, &r, 0, CMD_GEN, "orig_client=cli2");
	asfd_assert_write(asfd, &w, 0, CMD_GEN, "orig_client ok");

	// Should get the same as before, with orig_client added.
	// That is, it should not read from cli2's restore file.
	asfd_mock_read(asfd, &r, 0, CMD_GEN, "srestore ok");
	asfd_assert_write(asfd, &w, 0, CMD_GEN, "overwrite = 1");
	asfd_assert_write(asfd, &w, 0, CMD_GEN, "strip = 0");
	asfd_assert_write(asfd, &w, 0, CMD_GEN, "regex_case_insensitive = 0");
	asfd_assert_write(asfd, &w, 0, CMD_GEN, "orig_client = cli2");
	asfd_assert_write(asfd, &w, 0, CMD_GEN, "srestore end");
	asfd_mock_read(asfd, &r, 0, CMD_GEN, "srestore end ok");

	setup_send_features_proto_end(asfd, &r, &w);
}

static void checks_orig_client_srestore(struct conf **confs,
	struct conf **cconfs, const char *incexc, int srestore)
{
	struct stat statp;
	fail_unless(srestore==1);
	// Should not have deleted either restore file.
	fail_unless(!lstat(SRESTORE_FILE, &statp));
	fail_unless(!lstat(SRESTORE_FILE_CLI2, &statp));
}

START_TEST(test_server_extra_comms)
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

	run_test(0, setup_send_features_proto_1_1,
		NULL);
	run_test(0, setup_send_features_proto_2_2,
		NULL);

	run_test(-1, setup_unexpected_cmd_feature,
		NULL);

	run_test(0, setup_autoupgrade_no_os,
		NULL);
	run_test(0, setup_autoupgrade,
		NULL);

#ifdef HAVE_BLAKE2
	run_test(0, setup_rshash_blake2, checks_rshash_blake2);
#else
	run_test(-1, setup_rshash_blake2, checks_rshash_blake2);
#endif
	run_test(0, setup_counters_ok, checks_counters_ok);
	run_test(0, setup_msg, checks_msg);
	run_test(0, setup_uname, checks_uname);
	run_test(0, setup_uname_is_windows, checks_uname_is_windows);
	run_test(-1, setup_unexpected_feature, NULL);
	run_test(0, setup_srestore_not_ok, checks_srestore_not_ok);

	run_test(0, setup_srestore_ok, checks_srestore_ok);
	run_test(-1, setup_srestore_ok_error, NULL);
	run_test(0, setup_sincexc_ok, NULL);
	run_test(0, setup_incexc, checks_incexc);
	run_test(-1, setup_orig_client_not_existing, NULL);
	run_test(0, setup_orig_client, checks_orig_client);
	run_test(0, setup_orig_client_srestore, checks_orig_client_srestore);
}
END_TEST

Suite *suite_server_extra_comms(void)
{
	Suite *s;
	TCase *tc_core;

	s=suite_create("server_extra_comms");

	tc_core=tcase_create("Core");
	tcase_set_timeout(tc_core, 60);

	tcase_add_test(tc_core, test_server_extra_comms);

	suite_add_tcase(s, tc_core);

	return s;
}
