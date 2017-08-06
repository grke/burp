#include "../test.h"
#include "../builders/build_file.h"
#include "../../src/alloc.h"
#include "../../src/asfd.h"
#include "../../src/conf.h"
#include "../../src/conffile.h"
#include "../../src/fsops.h"
#include "../../src/iobuf.h"
#include "../../src/server/ca.h"
#include "../builders/build_asfd_mock.h"

#define CONF_BASE	"utest_server_ca"
#define CONFFILE	CONF_BASE "/burp-server.conf"
#define CCONFFILE	CONF_BASE "/utestclient"
#define CA_CONF		CONF_BASE "/ca_conf"

static struct ioevent_list areads;
static struct ioevent_list awrites;

static void tear_down(struct asfd **asfd,
	struct conf ***globalcs, struct conf ***cconfs)
{
	fail_unless(!recursive_delete(CONF_BASE));
	asfd_free(asfd);
	asfd_mock_teardown(&areads, &awrites);
	confs_free(globalcs);
	confs_free(cconfs);
	alloc_check();
}

static struct conf **setup_conf(void)
{
	struct conf **confs=NULL;
	fail_unless((confs=confs_alloc())!=NULL);
	fail_unless(!confs_init(confs));
	return confs;
}

static void setup(struct conf ***globalcs, struct conf ***cconfs,
	const char *extra_conf)
{
	char buf[4096];
	*globalcs=setup_conf();
	*cconfs=setup_conf();

	snprintf(buf, sizeof(buf), "%s%s", MIN_SERVER_CONF, extra_conf);
	build_file(CONFFILE, buf);
	build_file(CCONFFILE, "");
	build_file(CA_CONF, "blah\nCA_DIR=somedir\nasdflkj\n");
	fail_unless(!conf_load_global_only(CONFFILE, *globalcs));
	fail_unless(!conf_load_overrides(*globalcs, *cconfs, CCONFFILE));
}

static void check_version(struct conf **globalcs, struct conf **cconfs,
	int expected, const char *version)
{
	set_string(cconfs[OPT_PEER_VERSION], version);
	fail_unless(ca_server_maybe_sign_client_cert(NULL, globalcs, cconfs)
		==expected);
}

START_TEST(test_ca_server_maybe_sign_version_check)
{
	struct conf **globalcs=NULL;
	struct conf **cconfs=NULL;

	setup(&globalcs, &cconfs, "");

	// These return 0 straight away because clients less than version 1.3.2
	// did not know how to do cert signing requests.
	check_version(globalcs, cconfs, 0,  NULL);
	check_version(globalcs, cconfs, 0,  "");
	check_version(globalcs, cconfs, 0,  "1.3.1");
	// This returns an error because asfd is not set up.
	check_version(globalcs, cconfs, -1, "1.3.2");

	tear_down(NULL, &globalcs, &cconfs);
}
END_TEST

static void setup_asfd_nocsr(struct asfd *asfd)
{
	int r=0;
	int w=0;
	asfd_mock_read(asfd, &r, 0, CMD_GEN, "nocsr");
	asfd_assert_write(asfd, &w, 0, CMD_GEN, "nocsr ok");
}

static void setup_asfd_csr_no_ca_conf(struct asfd *asfd)
{
	int r=0;
	int w=0;
	asfd_mock_read(asfd, &r, 0, CMD_GEN, "csr");
	asfd_assert_write(asfd, &w, 0, CMD_ERROR, "server not configured to sign client certificates");
}

static void setup_asfd_unexpected(struct asfd *asfd)
{
	int r=0;
	asfd_mock_read(asfd, &r, 0, CMD_GEN, "blah");
}

static void do_test_ca_server_maybe_sign(
	int expected_ret,
	int do_extra_conf,
	void setup_asfd_callback(struct asfd *asfd))
{
	int result;
	struct asfd *asfd;
	struct conf **globalcs=NULL;
	struct conf **cconfs=NULL;
	const char *extra_conf=
		"ca_conf=" CA_CONF "\n"
		"ca_name=caname\n"
		"ca_server_name=caservername\n"
		"ca_burp_ca=caburpca\n"
		"ssl_key=sslkey\n";

	setup(&globalcs, &cconfs, do_extra_conf?extra_conf:"");
	asfd=asfd_mock_setup(&areads, &awrites);
	setup_asfd_callback(asfd);

	set_string(cconfs[OPT_PEER_VERSION], PACKAGE_VERSION);
	set_string(cconfs[OPT_CNAME], "utestclient");
	result=ca_server_maybe_sign_client_cert(asfd, globalcs, cconfs);
	fail_unless(result==expected_ret);

	tear_down(&asfd, &globalcs, &cconfs);
}

START_TEST(test_ca_server_maybe_sign)
{
	do_test_ca_server_maybe_sign(-1, 1, setup_asfd_unexpected);
	do_test_ca_server_maybe_sign(0,  0, setup_asfd_nocsr);
	do_test_ca_server_maybe_sign(-1, 0, setup_asfd_csr_no_ca_conf);
}
END_TEST

Suite *suite_server_ca(void)
{
	Suite *s;
	TCase *tc_core;

	s=suite_create("server_ca");

	tc_core=tcase_create("Core");

	tcase_add_test(tc_core, test_ca_server_maybe_sign_version_check);
	tcase_add_test(tc_core, test_ca_server_maybe_sign);

	suite_add_tcase(s, tc_core);

	return s;
}
