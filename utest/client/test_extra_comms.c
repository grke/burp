#include "../test.h"
#include "../../src/alloc.h"
#include "../../src/action.h"
#include "../../src/asfd.h"
#include "../../src/async.h"
#include "../../src/conf.h"
#include "../../src/fsops.h"
#include "../../src/iobuf.h"
#include "../../src/sbuf.h"
#include "../../src/strlist.h"
#include "../../src/client/extra_comms.h"
#include "../builders/build.h"
#include "../builders/build_file.h"
#include "../builders/build_asfd_mock.h"

#include <sys/utsname.h>

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

static void setup(struct async **as, struct conf ***confs)
{
	if(as) *as=setup_async();
	if(confs) *confs=setup_conf();
}

static void tear_down(struct async **as, struct asfd **asfd,
	struct conf ***confs)
{
	async_free(as);
	asfd_free(asfd);
	asfd_mock_teardown(&reads, &writes);
	confs_free(confs);
	alloc_check();
}

static int async_rw_simple(struct async *as)
{
	return as->asfd->read(as->asfd);
}

static void run_test(int expected_ret,
	enum action action,
	void setup_callback(struct asfd *asfd, struct conf **confs),
	void checks_callback(struct conf **confs,
		enum action action, const char *incexc))
{
        struct async *as;
        struct asfd *asfd;
        struct conf **confs;
	struct strlist *failover=NULL;
	char *incexc=NULL;

        setup(&as, &confs);
        asfd=asfd_mock_setup(&reads, &writes);
	as->asfd_add(as, asfd);
	as->read_write=async_rw_simple;
	asfd->as=as;

	setup_callback(asfd, confs);

	fail_unless(extra_comms_client(
		as,
		confs,
		&action,
		failover,
		&incexc
	)==expected_ret);

	if(checks_callback)
		checks_callback(confs, action, incexc);

	free_w(&incexc);
	tear_down(&as, &asfd, &confs);
}

static void setup_write_error(struct asfd *asfd, struct conf **confs)
{
	int w=0;
	asfd_assert_write(asfd, &w, -1, CMD_GEN, "extra_comms_begin");
}

static void setup_read_error(struct asfd *asfd, struct conf **confs)
{
	int r=0; int w=0;
	asfd_assert_write(asfd, &w, 0, CMD_GEN, "extra_comms_begin");
	asfd_mock_read(asfd, &r, -1, CMD_GEN, "extra_comms_begin ok");
}

static void setup_read_unexpected(struct asfd *asfd, struct conf **confs)
{
	int r=0; int w=0;
	asfd_assert_write(asfd, &w, 0, CMD_GEN, "extra_comms_begin");
	asfd_mock_read(asfd, &r, 0, CMD_GEN, "extra_comms_begin blah");
}

static void setup_extra_comms_begin(struct asfd *asfd,
	int *r, int *w, const char *feat)
{
	char msg[64];
	asfd_assert_write(asfd, w, 0, CMD_GEN, "extra_comms_begin");
	snprintf(msg, sizeof(msg), "extra_comms_begin ok:%s:", feat);
	asfd_mock_read(asfd, r, 0, CMD_GEN, msg);
}

static void setup_extra_comms_end(struct asfd *asfd, int *r, int *w)
{
	asfd_assert_write(asfd, w, 0, CMD_GEN, "extra_comms_end");
	asfd_mock_read(asfd, r, 0, CMD_GEN, "extra_comms_end ok");
}

static void setup_end_unexpected(struct asfd *asfd, struct conf **confs)
{
	int r=0; int w=0;
	setup_extra_comms_begin(asfd, &r, &w, "");
	asfd_assert_write(asfd, &w, 0, CMD_GEN, "extra_comms_end");
	asfd_mock_read(asfd, &r, 0, CMD_GEN, "extra_comms_end blah");
}

static void setup_autoupgrade(struct asfd *asfd, struct conf **confs)
{
	int r=0; int w=0;
	fail_unless(!set_string(confs[OPT_AUTOUPGRADE_DIR], "blah"));
	fail_unless(!set_string(confs[OPT_AUTOUPGRADE_OS], "os"));
	setup_extra_comms_begin(asfd, &r, &w, "autoupgrade");
	// Return an error from the autoupgrade code.
	asfd_assert_write(asfd, &w, -1, CMD_GEN, "autoupgrade:os");
}

static void setup_happy_path_simple(struct asfd *asfd,
	struct conf **confs)
{
	int r=0; int w=0;
	setup_extra_comms_begin(asfd, &r, &w, "");
	setup_extra_comms_end(asfd, &r, &w);
}

static void setup_srestore_action_monitor(struct asfd *asfd,
	struct conf **confs)
{
	int r=0; int w=0;
	setup_extra_comms_begin(asfd, &r, &w, "srestore");
	setup_extra_comms_end(asfd, &r, &w);
}

static void setup_srestore_denied(struct asfd *asfd, struct conf **confs)
{
	int r=0; int w=0;
	set_int(confs[OPT_SERVER_CAN_RESTORE], 0);
	setup_extra_comms_begin(asfd, &r, &w, "srestore");
	asfd_assert_write(asfd, &w, 0, CMD_GEN, "srestore not ok");
	setup_extra_comms_end(asfd, &r, &w);
}

// Neither client or server provide a restoreprefix
static void setup_srestore_no_restoreprefix1(
	struct asfd *asfd, struct conf **confs)
{
	int r=0; int w=0;
	set_int(confs[OPT_SERVER_CAN_RESTORE], 1);
	setup_extra_comms_begin(asfd, &r, &w, "srestore");
	asfd_assert_write(asfd, &w, 0, CMD_GEN, "srestore ok");

	asfd_mock_read(asfd, &r, 0, CMD_GEN, "backup = 20");
	asfd_mock_read(asfd, &r, 0, CMD_GEN, "srestore end");
	asfd_assert_write(asfd, &w, 0, CMD_GEN, "srestore end ok");
}

// Server provides a restoreprefix, but the client does not.
static void setup_srestore_no_restoreprefix2(
	struct asfd *asfd, struct conf **confs)
{
	int r=0; int w=0;
	set_int(confs[OPT_SERVER_CAN_RESTORE], 1);
	setup_extra_comms_begin(asfd, &r, &w, "srestore");
	asfd_assert_write(asfd, &w, 0, CMD_GEN, "srestore ok");

	asfd_mock_read(asfd, &r, 0, CMD_GEN, "backup = 20");
	asfd_mock_read(asfd, &r, 0, CMD_GEN, "restoreprefix = /tmp");
	asfd_mock_read(asfd, &r, 0, CMD_GEN, "srestore end");
	asfd_assert_write(asfd, &w, 0, CMD_GEN, "srestore end ok");
}

static void setup_srestore(struct asfd *asfd, struct conf **confs)
{
	int r=0; int w=0;
	set_int(confs[OPT_SERVER_CAN_RESTORE], 1);
	set_string(confs[OPT_RESTOREPREFIX], "/tmp");
	setup_extra_comms_begin(asfd, &r, &w, "srestore");
	asfd_assert_write(asfd, &w, 0, CMD_GEN, "srestore ok");

	asfd_mock_read(asfd, &r, 0, CMD_GEN, "backup = 20");
	asfd_mock_read(asfd, &r, 0, CMD_GEN, "include = /blah1");
	asfd_mock_read(asfd, &r, 0, CMD_GEN, "include = /blah2");
	asfd_mock_read(asfd, &r, 0, CMD_GEN, "srestore end");
	asfd_assert_write(asfd, &w, 0, CMD_GEN, "srestore end ok");

	setup_extra_comms_end(asfd, &r, &w);
}

static void check_srestore(struct conf **confs,
	enum action action, const char *incexc)
{
	struct strlist *s;
	fail_unless(!strcmp(incexc,
		"backup = 20\ninclude = /blah1\ninclude = /blah2\n\n"));
	s=get_strlist(confs[OPT_INCLUDE]);
	fail_unless(!strcmp(s->path, "/blah1"));
	fail_unless(!strcmp(s->next->path, "/blah2"));
	fail_unless(s->next->next==NULL);
	fail_unless(!strcmp(get_string(confs[OPT_BACKUP]), "20"));
	fail_unless(action==ACTION_RESTORE);
	fail_unless(get_string(confs[OPT_ORIG_CLIENT])==NULL);
}

static void setup_srestore_orig_client(struct asfd *asfd, struct conf **confs)
{
	int r=0; int w=0;
	set_int(confs[OPT_SERVER_CAN_RESTORE], 1);
	set_string(confs[OPT_RESTOREPREFIX], "/tmp");
	setup_extra_comms_begin(asfd, &r, &w, "srestore:orig_client");
	asfd_assert_write(asfd, &w, 0, CMD_GEN, "srestore ok");

	asfd_mock_read(asfd, &r, 0, CMD_GEN, "backup = 10");
	asfd_mock_read(asfd, &r, 0, CMD_GEN, "include = /blah1");
	asfd_mock_read(asfd, &r, 0, CMD_GEN, "orig_client = altclient");
	asfd_mock_read(asfd, &r, 0, CMD_GEN, "srestore end");
	asfd_assert_write(asfd, &w, 0, CMD_GEN, "srestore end ok");
	asfd_assert_write(asfd, &w, 0, CMD_GEN, "orig_client=altclient");
	asfd_mock_read(asfd, &r, 0, CMD_GEN, "orig_client ok");

	setup_extra_comms_end(asfd, &r, &w);
}

static void check_srestore_orig_client(struct conf **confs,
	enum action action, const char *incexc)
{
	fail_unless(!strcmp(incexc, "backup = 10\ninclude = /blah1\norig_client = altclient\n\n"));
	fail_unless(!strcmp(get_string(confs[OPT_BACKUP]), "10"));
	fail_unless(action==ACTION_RESTORE);
	fail_unless(!strcmp(get_string(confs[OPT_ORIG_CLIENT]), "altclient"));
}

static void setup_switch_client_denied(struct asfd *asfd, struct conf **confs)
{
	int r=0; int w=0;
	fail_unless(!set_string(confs[OPT_CNAME], "testclient"));
	fail_unless(!set_string(confs[OPT_ORIG_CLIENT], "abc"));
	setup_extra_comms_begin(asfd, &r, &w, "");
}

static void setup_switch_client(struct asfd *asfd, struct conf **confs)
{
	int r=0; int w=0;
	fail_unless(!set_string(confs[OPT_CNAME], "testclient"));
	fail_unless(!set_string(confs[OPT_ORIG_CLIENT], "abc"));
	setup_extra_comms_begin(asfd, &r, &w, "orig_client");
	asfd_assert_write(asfd, &w, 0, CMD_GEN, "orig_client=abc");
	asfd_mock_read(asfd, &r, 0, CMD_GEN, "orig_client ok");
	setup_extra_comms_end(asfd, &r, &w);
}

static void setup_switch_client_read_unexpected(struct asfd *asfd,
	struct conf **confs)
{
	int r=0; int w=0;
	fail_unless(!set_string(confs[OPT_CNAME], "testclient"));
	fail_unless(!set_string(confs[OPT_ORIG_CLIENT], "abc"));
	setup_extra_comms_begin(asfd, &r, &w, "orig_client");
	asfd_assert_write(asfd, &w, 0, CMD_GEN, "orig_client=abc");
	asfd_mock_read(asfd, &r, 0, CMD_GEN, "orig_client blah");
}

static void setup_sincexc_denied(struct asfd *asfd, struct conf **confs)
{
	int r=0; int w=0;
	set_int(confs[OPT_SERVER_CAN_OVERRIDE_INCLUDES], 0);
	setup_extra_comms_begin(asfd, &r, &w, "sincexc");
	setup_extra_comms_end(asfd, &r, &w);
}

static void check_sincexc(struct conf **confs,
	enum action action, const char *incexc)
{
	struct strlist *s;
	fail_unless(!strcmp(incexc,
		"include = /blah1\ninclude = /blah2\n\n"));
	s=get_strlist(confs[OPT_INCLUDE]);
	fail_unless(!strcmp(s->path, "/blah1"));
	fail_unless(!strcmp(s->next->path, "/blah2"));
	fail_unless(s->next->next==NULL);
	fail_unless(action==ACTION_BACKUP);
}

static void setup_sincexc(struct asfd *asfd, struct conf **confs)
{
	int r=0; int w=0;
	setup_extra_comms_begin(asfd, &r, &w, "sincexc");
	set_int(confs[OPT_SERVER_CAN_OVERRIDE_INCLUDES], 1);
	asfd_assert_write(asfd, &w, 0, CMD_GEN, "sincexc ok");
	asfd_mock_read(asfd, &r, 0, CMD_GEN, "include = /blah1");
	asfd_mock_read(asfd, &r, 0, CMD_GEN, "include = /blah2");
	asfd_mock_read(asfd, &r, 0, CMD_GEN, "sincexc end");
	asfd_assert_write(asfd, &w, 0, CMD_GEN, "sincexc end ok");
	setup_extra_comms_end(asfd, &r, &w);
}

static void check_counters(struct conf **confs,
	enum action action, const char *incexc)
{
	fail_unless(get_int(confs[OPT_SEND_CLIENT_CNTR])==1);
}

static void setup_counters(struct asfd *asfd, struct conf **confs)
{
	int r=0; int w=0;
	setup_extra_comms_begin(asfd, &r, &w, "counters_json");
	asfd_assert_write(asfd, &w, 0, CMD_GEN, "counters_json ok");
	setup_extra_comms_end(asfd, &r, &w);
}

static void setup_uname(struct asfd *asfd, struct conf **confs)
{
	char msg[512]="";
	int r=0; int w=0;
	struct utsname utsname;
	fail_unless(!uname(&utsname));
	snprintf(msg, sizeof(msg), "uname=%s", utsname.sysname);
	setup_extra_comms_begin(asfd, &r, &w, "uname");
	asfd_assert_write(asfd, &w, 0, CMD_GEN, msg);
	setup_extra_comms_end(asfd, &r, &w);
}

static void check_msg(struct conf **confs,
	enum action action, const char *incexc)
{
	fail_unless(get_int(confs[OPT_MESSAGE])==1);
}

static void setup_msg(struct asfd *asfd, struct conf **confs)
{
	int r=0; int w=0;
	setup_extra_comms_begin(asfd, &r, &w, "msg");
	asfd_assert_write(asfd, &w, 0, CMD_GEN, "msg");
	setup_extra_comms_end(asfd, &r, &w);
}

static void check_rshash(struct conf **confs,
	enum action action, const char *incexc)
{
	fail_unless(get_e_rshash(confs[OPT_RSHASH])==
#ifdef HAVE_BLAKE2
		RSHASH_BLAKE2
#else
		RSHASH_MD4
#endif
	);
}

static void setup_rshash(struct asfd *asfd, struct conf **confs)
{
	int r=0; int w=0;
	setup_extra_comms_begin(asfd, &r, &w, "rshash=blake2");
#ifdef HAVE_BLAKE2
	asfd_assert_write(asfd, &w, 0, CMD_GEN, "rshash=blake2");
#endif
	setup_extra_comms_end(asfd, &r, &w);
}

START_TEST(test_client_extra_comms)
{
	run_test(-1, ACTION_BACKUP, setup_write_error, NULL);
	run_test(-1, ACTION_BACKUP, setup_read_error, NULL);
	run_test(-1, ACTION_BACKUP, setup_read_unexpected, NULL);
	run_test(-1, ACTION_BACKUP, setup_autoupgrade, NULL);
	run_test(0,  ACTION_BACKUP, setup_happy_path_simple, NULL);
	run_test(-1, ACTION_BACKUP, setup_end_unexpected, NULL);
	run_test(0,  ACTION_BACKUP, setup_srestore_denied, NULL);
	run_test(0,  ACTION_MONITOR,setup_srestore_action_monitor, NULL);
	run_test(0,  ACTION_BACKUP, setup_srestore, check_srestore);
	run_test(-1,  ACTION_BACKUP, setup_srestore_no_restoreprefix1, NULL);
	run_test(-1,  ACTION_BACKUP, setup_srestore_no_restoreprefix2, NULL);
	run_test(0,  ACTION_BACKUP,
		setup_srestore_orig_client, check_srestore_orig_client);
	run_test(-1, ACTION_BACKUP, setup_switch_client_denied, NULL);
	run_test(0,  ACTION_BACKUP, setup_switch_client, NULL);
	run_test(-1, ACTION_BACKUP, setup_switch_client_read_unexpected, NULL);
	run_test(0,  ACTION_BACKUP, setup_sincexc_denied, NULL);
	run_test(0,  ACTION_BACKUP, setup_sincexc, check_sincexc);
	run_test(0,  ACTION_BACKUP, setup_counters, check_counters);
	run_test(0,  ACTION_BACKUP, setup_uname, NULL);
	run_test(0,  ACTION_BACKUP, setup_msg, check_msg);
	run_test(0,  ACTION_BACKUP, setup_rshash, check_rshash);
}
END_TEST

Suite *suite_client_extra_comms(void)
{
	Suite *s;
	TCase *tc_core;

	s=suite_create("client_extra_comms");

	tc_core=tcase_create("Core");
	tcase_set_timeout(tc_core, 60);

	tcase_add_test(tc_core, test_client_extra_comms);

	suite_add_tcase(s, tc_core);

	return s;
}
