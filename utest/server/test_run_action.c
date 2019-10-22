#include "../test.h"
#include "../src/action.h"
#include "../src/alloc.h"
#include "../src/asfd.h"
#include "../src/async.h"
#include "../src/conf.h"
#include "../src/conffile.h"
#include "../src/fsops.h"
#include "../src/iobuf.h"
#include "../src/server/run_action.h"
#include "../builders/build_asfd_mock.h"
#include "../builders/build_file.h"

#define BASE		"utest_server_run_action"
#define CLIENTCONFDIR   "clientconfdir"
#define GLOBAL_CONF	BASE "/burp-server.conf"
#define CLIENTNAME	"utestclient"
#define CCONFFILE	CLIENTCONFDIR "/" CLIENTNAME

struct parsedata
{
	const char *str;
	enum action act;
	const char *backupnostr;
	const char *restoreregex;
	const char *input;
	int ret;
};

static struct parsedata pd[] = {
	{ "restore 1:regex", ACTION_RESTORE, "1", "regex", NULL, 0 },
	{ "restore 2:", ACTION_RESTORE, "2", NULL, NULL, 0 },
	{ "restore 3", ACTION_RESTORE, "3", NULL, NULL, 0 },
	{ "restore restore_list 1:regex", ACTION_RESTORE, "1", "regex", "", 0 },
	{ "restore restore_list 2:", ACTION_RESTORE, "2", NULL, "", 0 },
	{ "restore restore_list 3", ACTION_RESTORE, "3", NULL, "", 0 },
	{ "verify 1:regex", ACTION_VERIFY, "1", "regex", NULL, 0 },
	{ "verify 2:", ACTION_VERIFY, "2", NULL, NULL, 0 },
	{ "verify 3", ACTION_VERIFY, "3", NULL, NULL, 0 },
	{ "backup 3", (enum action)0, NULL, NULL, NULL, -1 },
	{ "verify restore_list 1:regex", ACTION_VERIFY, "1", "regex", "", 0 },
	{ "verify restore_list 2:", ACTION_VERIFY, "2", NULL, "", 0 },
	{ "verify restore_list 3", ACTION_VERIFY, "3", NULL, "", 0 },
	{ "restore1:regex", (enum action)0, NULL, NULL, NULL, -1 },
	{ "", (enum action)0, NULL, NULL, NULL, -1 },
	{ NULL, (enum action)0, NULL, NULL, NULL, -1 },
};

static void run_parse_test(struct parsedata *p)
{
	int ret;
	enum action act;
	struct conf **confs=NULL;
	confs=confs_alloc();
	confs_init(confs);

	ret=parse_restore_str_and_set_confs(p->str, &act, confs);
	fail_unless(ret==p->ret);
	if(!ret)
	{
		const char *backupnostr=NULL;
		const char *restoreregex=NULL;
		const char *input=NULL;
		fail_unless(act==p->act);
		backupnostr=get_string(confs[OPT_BACKUP]);
		restoreregex=get_string(confs[OPT_REGEX]);
		input=get_string(confs[OPT_RESTORE_LIST]);
		fail_unless(!strcmp(backupnostr, p->backupnostr));
		if(p->restoreregex)
			fail_unless(!strcmp(restoreregex, p->restoreregex));
		else
			fail_unless(restoreregex==NULL);
		if(p->input)
			fail_unless(!strcmp(input, p->input));
		else
			fail_unless(input==NULL);
	}

	confs_free(&confs);
	alloc_check();
}

START_TEST(test_parse_restore_str_and_set_confs)
{
	FOREACH(pd)
	{
		run_parse_test(&pd[i]);
	}
}
END_TEST

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

static struct cntr *setup_cntr(void)
{
	struct cntr *cntr;
	fail_unless((cntr=cntr_alloc())!=NULL);
	fail_unless(!cntr_init(cntr, CLIENTNAME, /*pid*/1234));
	return cntr;
}

static void clean(void)
{
	fail_unless(!recursive_delete(BASE));
	fail_unless(!recursive_delete(CLIENTCONFDIR));
}

static void setup(struct async **as,
	struct conf ***confs, struct conf ***cconfs, struct cntr **cntr)
{
	clean();
	*as=setup_async();
	*confs=setup_conf();
	*cconfs=setup_conf();
	*cntr=setup_cntr();
}

static void tear_down(struct async **as, struct asfd **asfd,
	struct conf ***confs, struct conf ***cconfs)
{
	clean();
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

static void setup_could_not_mkpath(struct asfd *asfd)
{
	int w=0;
	asfd_assert_write(asfd, &w, 0, CMD_ERROR,
		"could not mkpath " BASE "/directory/a_group/clients/utestclient/current");
}

static void build_directory_path(void)
{
	char path[256]="";
	snprintf(path, sizeof(path), BASE "/directory/a_group/clients/utestclient/current");
	fail_unless(!build_path_w(path));
}

static void setup_unknown_command(struct asfd *asfd)
{
	int w=0;
	build_directory_path();
	asfd_assert_write(asfd, &w, 0, CMD_ERROR, "unknown command");
}

static void set_rbuf(struct asfd *asfd, enum cmd cmd, const char *str)
{
	struct iobuf *rbuf=asfd->rbuf;
	rbuf->cmd=cmd;
	fail_unless((rbuf->buf=strdup_w(str, __func__))!=NULL);
}

static void setup_unknown_command_gen(struct asfd *asfd)
{
	int w=0;
	build_directory_path();
	set_rbuf(asfd, CMD_GEN, "blah ");
	asfd_assert_write(asfd, &w, 0, CMD_ERROR, "unknown command");
}

static void setup_list(struct asfd *asfd)
{
	int w=0;
	build_directory_path();
	set_rbuf(asfd, CMD_GEN, "list ");
	asfd_assert_write(asfd, &w, 0, CMD_GEN, "ok");
	asfd_assert_write(asfd, &w, 0, CMD_MESSAGE, "no backups");
}

static void setup_diff(struct asfd *asfd)
{
	int w=0;
	build_directory_path();
	set_rbuf(asfd, CMD_GEN, "diff ");
	asfd_assert_write(asfd, &w, 0, CMD_GEN, "ok");
	asfd_assert_write(asfd, &w, 0,
		CMD_ERROR, "you need to specify two backups");
}

static void setup_backup(struct asfd *asfd)
{
	int r=0;
	int w=0;
	build_directory_path();
	set_rbuf(asfd, CMD_GEN, "backup ");
	asfd_assert_write(asfd, &w, 0, CMD_GEN, "ok:9");
	asfd_mock_read(asfd, &r, 0, CMD_GEN, "ok");
}

static void setup_restore(struct asfd *asfd)
{
	int w=0;
	build_directory_path();
	set_rbuf(asfd, CMD_GEN, "restore ");
	asfd_assert_write(asfd, &w, 0, CMD_GEN, "ok");
	asfd_assert_write(asfd, &w, 0, CMD_ERROR, "backup not found");
}

static void setup_verify(struct asfd *asfd)
{
	int w=0;
	build_directory_path();
	set_rbuf(asfd, CMD_GEN, "verify ");
	asfd_assert_write(asfd, &w, 0, CMD_GEN, "ok");
	asfd_assert_write(asfd, &w, 0, CMD_ERROR, "backup not found");
}

static void setup_delete(struct asfd *asfd)
{
	build_directory_path();
	set_rbuf(asfd, CMD_GEN, "Delete ");
}

static void setup_delete_old_style(struct asfd *asfd)
{
	int w=0;
	build_directory_path();
	set_rbuf(asfd, CMD_GEN, "delete ");
	asfd_assert_write(asfd, &w, 0, CMD_ERROR,
		"old style delete is not supported on this server");
}

static void run_test(
	int expected_ret,
	void setup_callback(struct asfd *)
)
{
	struct async *as;
	struct asfd *asfd;
	struct conf **confs;
	struct conf **cconfs;
	struct cntr *cntr;
	int timer_ret=0;

	setup(&as, &confs, &cconfs, &cntr);
	set_cntr(cconfs[OPT_CNTR], cntr);
	asfd=asfd_mock_setup(&reads, &writes);
	as->asfd_add(as, asfd);
	as->read_write=async_rw_simple;
	asfd->as=as;

	build_file(GLOBAL_CONF,
		MIN_SERVER_CONF
		"directory=" BASE "/directory\n");
	build_file(CCONFFILE, "");
	fail_unless(!conf_load_global_only(GLOBAL_CONF, confs));
	fail_unless(!conf_load_overrides(confs, cconfs, CCONFFILE));
	fail_unless(!set_string(cconfs[OPT_CNAME], "utestclient"));
	setup_callback(asfd);

	fail_unless(run_action_server(
		as,
		NULL, // incexc
		0, // srestore
		&timer_ret,
		cconfs)==expected_ret);

	tear_down(&as, &asfd, &confs, &cconfs);
}

START_TEST(test_run_action)
{
	run_test(-1, setup_could_not_mkpath);
	run_test(-1, setup_unknown_command);
	run_test(-1, setup_unknown_command_gen);
	run_test(0, setup_list);
	run_test(-1, setup_diff);
	run_test(-1, setup_backup);
	run_test(-1, setup_restore);
	run_test(-1, setup_verify);
	run_test(0, setup_delete);
	run_test(-1, setup_delete_old_style);
}
END_TEST

Suite *suite_server_run_action(void)
{
	Suite *s;
	TCase *tc_core;

	s=suite_create("server_run_action");

	tc_core=tcase_create("Core");
	tcase_add_test(tc_core, test_parse_restore_str_and_set_confs);
	tcase_add_test(tc_core, test_run_action);

	suite_add_tcase(s, tc_core);

	return s;
}
