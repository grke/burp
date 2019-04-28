#include <check.h>
#include <stdio.h>
#include <stdlib.h>
#include "test.h"
#include "builders/build_file.h"
#include "../src/alloc.h"
#include "../src/conf.h"
#include "../src/conffile.h"
#include "../src/fsops.h"
#include "../src/pathcmp.h"

#define BASE		"utest_conffile"
#define CONFFILE	BASE "/burp.conf"

static struct conf **setup_conf(void)
{
	struct conf **confs=NULL;
	fail_unless((confs=confs_alloc())!=NULL);
	fail_unless(!confs_init(confs));
	return confs;
}

static void setup(struct conf ***globalcs, struct conf ***cconfs)
{
	fail_unless(recursive_delete(BASE)==0);
	alloc_counters_reset();
	if(globalcs) *globalcs=setup_conf();
	if(cconfs) *cconfs=setup_conf();
}

static void tear_down(struct conf ***globalcs, struct conf ***confs)
{
	fail_unless(recursive_delete(BASE)==0);
	confs_free(confs);
	confs_free(globalcs);
	alloc_check();
}

struct data
{
	const char *str;
	const char *field;
	const char *value;
	int reset;
};

static struct data d[] = {
	{ "a=b", "a", "b", 0 },
	{ "a=b\n", "a", "b", 0 },
	{ "a = b", "a", "b", 0 },
	{ "   a  =    b ", "a", "b", 0 },
	{ "   a  =    b \n", "a", "b", 0 },
	{ "#a=b", NULL, NULL, 0 },
	{ "  #a=b", NULL, NULL, 0 },
	{ "a='b'", "a", "b", 0 },
	{ "a='b", "a", "b", 0 },
	{ "a=b'", "a", "b'", 0 },
	{ "a=\"b\"", "a", "b", 0 },
	{ "a=b\"", "a", "b\"", 0 },
	{ "a=\"b", "a", "b", 0 },
	{ "a=b # comment", "a", "b # comment", 0 }, // Maybe fix this.
	{ "field=longvalue with spaces", "field", "longvalue with spaces", 0 },
	{ "test:=reset", "test", "reset", 1 },
};

START_TEST(test_conf_get_pair)
{
	FOREACH(d)
	{
		char *field=NULL;
		char *value=NULL;
		char *str=strdup(d[i].str);
		int reset=0;
		conf_get_pair(str, &field, &value, &reset);
		if(!field || !d[i].field)
			fail_unless(field==d[i].field);
		else
			fail_unless(!strcmp(field, d[i].field));
		if(!value || !d[i].value)
			fail_unless(value==d[i].value);
		else
			fail_unless(!strcmp(value, d[i].value));
		fail_unless(d[i].reset==reset);
		free(str);
	}
}
END_TEST

static void assert_strlist(struct strlist **s, const char *path, int flag)
{
	if(!path)
	{
		fail_unless(*s==NULL);
		return;
	}
	ck_assert_str_eq((*s)->path, path);
	fail_unless((*s)->flag==flag);
	*s=(*s)->next;
}

static void check_listen(struct conf **confs,
	const char *listen, int max_children,
	const char *listen_status, int max_status_children)
{
	struct strlist *s;
	s=get_strlist(confs[OPT_LISTEN]);
	assert_strlist(&s, listen, max_children);
	s=get_strlist(confs[OPT_LISTEN_STATUS]);
	assert_strlist(&s, listen_status, max_status_children);
}

static void check_ports(struct conf **confs,
	const char *port, int max_children,
	const char *status_port, int max_status_children)
{
	struct strlist *s;
	s=get_strlist(confs[OPT_PORT]);
	assert_strlist(&s, port, max_children);
	s=get_strlist(confs[OPT_STATUS_PORT]);
	assert_strlist(&s, status_port, max_status_children);
}

START_TEST(test_client_conf)
{
	struct conf **confs=NULL;
	setup(&confs, NULL);
	build_file(CONFFILE, MIN_CLIENT_CONF);
	fail_unless(!conf_load_global_only(CONFFILE, confs));
	fail_unless(get_e_burp_mode(confs[OPT_BURP_MODE])==BURP_MODE_CLIENT);
	ck_assert_str_eq(get_string(confs[OPT_SERVER]), "4.5.6.7");
	check_ports(confs, "1234", 0, "12345", 0);
	ck_assert_str_eq(get_string(confs[OPT_LOCKFILE]), "/lockfile/path");
	ck_assert_str_eq(get_string(confs[OPT_SSL_CERT]), "/ssl/cert/path");
	ck_assert_str_eq(get_string(confs[OPT_SSL_CERT_CA]), "/cert_ca/path");
	ck_assert_str_eq(get_string(confs[OPT_SSL_PEER_CN]), "my_cn");
	ck_assert_str_eq(get_string(confs[OPT_SSL_KEY]), "/ssl/key/path");
	ck_assert_str_eq(get_string(confs[OPT_CA_CSR_DIR]), "/csr/dir");
	tear_down(NULL, &confs);
}
END_TEST

static void check_client_ports(struct conf **confs,
	int p_backup, int p_restore, int p_verify, int p_list, int p_delete)
{
	fail_unless(get_int(confs[OPT_PORT_BACKUP])==p_backup);
	fail_unless(get_int(confs[OPT_PORT_RESTORE])==p_restore);
	fail_unless(get_int(confs[OPT_PORT_VERIFY])==p_verify);
	fail_unless(get_int(confs[OPT_PORT_LIST])==p_list);
	fail_unless(get_int(confs[OPT_PORT_DELETE])==p_delete);
}

START_TEST(test_client_conf_monitor_exe)
{
	struct conf **confs=NULL;
	setup(&confs, NULL);
	build_file(CONFFILE, MIN_CLIENT_CONF
		"monitor_exe=/some/path"
	);
	fail_unless(!conf_load_global_only(CONFFILE, confs));
	ck_assert_str_eq(get_string(confs[OPT_MONITOR_EXE]), "/some/path");
	tear_down(NULL, &confs);
}
END_TEST

START_TEST(test_client_conf_ports_opt_port_only)
{
	struct conf **confs=NULL;
	setup(&confs, NULL);
	build_file(CONFFILE, MIN_CLIENT_CONF);
	fail_unless(!conf_load_global_only(CONFFILE, confs));
	check_client_ports(confs, 1234, 1234, 1234, 1234, 1234);
	tear_down(NULL, &confs);
}
END_TEST

START_TEST(test_client_conf_ports_opt_port_and_restore)
{
	struct conf **confs=NULL;
	setup(&confs, NULL);
	build_file(CONFFILE, MIN_CLIENT_CONF_NO_PORTS
		"port=1234\n"
		"port_restore=5555\n"
	);
	fail_unless(!conf_load_global_only(CONFFILE, confs));
	check_client_ports(confs, 1234, 5555, 5555, 1234, 1234);
	tear_down(NULL, &confs);
}
END_TEST

START_TEST(test_client_conf_ports_opt_port_and_all)
{
	struct conf **confs=NULL;
	setup(&confs, NULL);
	build_file(CONFFILE, MIN_CLIENT_CONF_NO_PORTS
		"port=1234\n"
		"port_backup=2345\n"
		"port_restore=3456\n"
		"port_verify=4567\n"
		"port_list=5678\n"
		"port_delete=6789\n"
	);
	fail_unless(!conf_load_global_only(CONFFILE, confs));
	check_client_ports(confs, 2345, 3456, 4567, 5678, 6789);
	tear_down(NULL, &confs);
}
END_TEST

START_TEST(test_client_conf_ports_no_opt_port_and_all)
{
	struct conf **confs=NULL;
	setup(&confs, NULL);
	build_file(CONFFILE, MIN_CLIENT_CONF_NO_PORTS
		"port_backup=2345\n"
		"port_restore=3456\n"
		"port_verify=4567\n"
		"port_list=5678\n"
		"port_delete=6789\n"
	);
	fail_unless(!conf_load_global_only(CONFFILE, confs));
	check_client_ports(confs, 2345, 3456, 4567, 5678, 6789);
	tear_down(NULL, &confs);
}
END_TEST

START_TEST(test_client_conf_ca_conf_problems)
{
	const char *buf="mode=client\n"
		"server=4.5.6.7\n"
		"port=1234\n"
		"status_port=12345\n"
		"lockfile=/lockfile/path\n"
		"ca_burp_ca=blah\n"
	;
	struct conf **confs=NULL;
	setup(&confs, NULL);
	build_file(CONFFILE, buf);
	fail_unless(conf_load_global_only(CONFFILE, confs)==-1);
	tear_down(NULL, &confs);
}
END_TEST

static void assert_include(struct strlist **s, const char *path)
{
	assert_strlist(s, path, 1);
}

static void assert_exclude(struct strlist **s, const char *path)
{
	assert_strlist(s, path, 0);
}

START_TEST(test_client_includes_excludes)
{
	const char *buf=MIN_CLIENT_CONF
		"exclude=/z\n"
		"exclude=/a/b\n"
		"include=/a/b/c\n"
		"include=/x/y/z\n"
		"include=/r/s/t\n"
		"include=/a\n"
		"include=/a/b/c/d\n"
		"cross_filesystem=/mnt/x\n"
		"cross_filesystem=/mnt/y/\n"
	;
	struct strlist *s;
	struct conf **confs=NULL;
	setup(&confs, NULL);
	build_file(CONFFILE, buf);
	fail_unless(!conf_load_global_only(CONFFILE, confs));
	s=get_strlist(confs[OPT_INCLUDE]);
	assert_include(&s, "/a");
	assert_include(&s, "/a/b/c");
	assert_include(&s, "/a/b/c/d");
	assert_include(&s, "/r/s/t");
	assert_include(&s, "/x/y/z");
	assert_include(&s, NULL);
	s=get_strlist(confs[OPT_EXCLUDE]);
	assert_exclude(&s, "/a/b");
	assert_exclude(&s, "/z");
	assert_exclude(&s, NULL);
	s=get_strlist(confs[OPT_STARTDIR]);
	assert_include(&s, "/a");
	assert_include(&s, "/r/s/t");
	assert_include(&s, "/x/y/z");
	assert_include(&s, NULL);
	s=get_strlist(confs[OPT_INCEXCDIR]);
	assert_include(&s, "/a");
	assert_exclude(&s, "/a/b");
	assert_include(&s, "/a/b/c");
	assert_include(&s, "/a/b/c/d");
	assert_include(&s, "/r/s/t");
	assert_include(&s, "/x/y/z");
	assert_exclude(&s, "/z");
	assert_include(&s, NULL);
	s=get_strlist(confs[OPT_FSCHGDIR]);
	assert_strlist(&s, "/a/b/c", 0);
	assert_strlist(&s, "/a/b/c/d", 0);
	assert_strlist(&s, "/mnt/x", 0);
	assert_strlist(&s, "/mnt/y", 0);
	assert_strlist(&s, NULL, 0);
	tear_down(NULL, &confs);
}
END_TEST

static const char *include_failures[] = {
	MIN_CLIENT_CONF "include=not_absolute\n",
	MIN_CLIENT_CONF "include=/\ninclude=/\n"
};

START_TEST(test_client_include_failures)
{
	struct conf **confs=NULL;
	FOREACH(include_failures)
	{
		setup(&confs, NULL);
		build_file(CONFFILE, include_failures[i]);
		fail_unless(conf_load_global_only(CONFFILE, confs)==-1);
		tear_down(NULL, &confs);
	}
}
END_TEST

START_TEST(test_client_include_glob)
{
	char cwd[1024];
	char buf[4096];
	char path1[2048];
	char path2[2048];
	struct strlist *s;
	struct conf **confs=NULL;
	fail_unless(getcwd(cwd, sizeof(cwd))!=NULL);
	snprintf(buf, sizeof(buf),
		"%sinclude_glob=%s/%s/*.glob\ninclude=/1\n",
		MIN_CLIENT_CONF, cwd, BASE);
	snprintf(path1, sizeof(path1), "%s/%s/a.glob", cwd, BASE);
	snprintf(path2, sizeof(path2), "%s/%s/b.glob", cwd, BASE);
	setup(&confs, NULL);
	build_file(CONFFILE, buf);

	fail_unless(!conf_load_global_only(CONFFILE, confs));
	s=get_strlist(confs[OPT_INCLUDE]);
	assert_include(&s, "/1");
	assert_include(&s, NULL);

	build_file(path1, "a");
	fail_unless(!reeval_glob(confs));
	s=get_strlist(confs[OPT_INCLUDE]);
	assert_include(&s, "/1");
	assert_include(&s, path1);
	assert_include(&s, NULL);

	build_file(path2, "b");
	fail_unless(!reeval_glob(confs));
	s=get_strlist(confs[OPT_INCLUDE]);
	assert_include(&s, "/1");
	assert_include(&s, path1);
	assert_include(&s, path2);
	assert_include(&s, NULL);

	tear_down(NULL, &confs);
}
END_TEST

START_TEST(test_server_conf)
{
	struct strlist *s;
	struct conf **confs=NULL;
	setup(&confs, NULL);
	build_file(CONFFILE, MIN_SERVER_CONF);
	fail_unless(!conf_load_global_only(CONFFILE, confs));
	fail_unless(get_e_burp_mode(confs[OPT_BURP_MODE])==BURP_MODE_SERVER);
	check_listen(confs, "0.0.0.0:1234", 5, "0.0.0.0:12345", 5);
	ck_assert_str_eq(get_string(confs[OPT_LOCKFILE]), "/lockfile/path");
	ck_assert_str_eq(get_string(confs[OPT_SSL_CERT]), "/ssl/cert/path");
	ck_assert_str_eq(get_string(confs[OPT_SSL_CERT_CA]), "/cert_ca/path");
	ck_assert_str_eq(get_string(confs[OPT_DIRECTORY]), "/a/directory");
	ck_assert_str_eq(get_string(confs[OPT_DEDUP_GROUP]), "a_group");
	ck_assert_str_eq(get_string(confs[OPT_CLIENTCONFDIR]), "clientconfdir");
	ck_assert_str_eq(get_string(confs[OPT_SSL_DHFILE]), "/a/dhfile");
	s=get_strlist(confs[OPT_KEEP]);
	assert_strlist(&s, "10", 10);
	assert_include(&s, NULL);
	tear_down(NULL, &confs);
}
END_TEST

START_TEST(test_server_port_conf_one_max_child)
{
	struct conf **confs=NULL;
	setup(&confs, NULL);
	build_file(CONFFILE, MIN_SERVER_CONF_NO_LISTEN
		"listen=0.0.0.0:1234\n"
		"listen_status=0.0.0.0:12345\n"
		"max_children=12\n"
		"max_status_children=21\n");
	fail_unless(!conf_load_global_only(CONFFILE, confs));
	check_listen(confs, "0.0.0.0:1234", 12, "0.0.0.0:12345", 21);
	tear_down(NULL, &confs);
}
END_TEST

START_TEST(test_server_port_conf_too_many_max_child)
{
	struct conf **confs=NULL;
	setup(&confs, NULL);
	build_file(CONFFILE, MIN_SERVER_CONF_NO_LISTEN
		"port=1234\n"
		"max_children=12\n"
		"max_children=21\n");
	fail_unless(conf_load_global_only(CONFFILE, confs)==-1);
	fail_unless(get_strlist(confs[OPT_STATUS_PORT])==NULL);
	tear_down(NULL, &confs);
}
END_TEST

START_TEST(test_server_port_conf_few_max_child)
{
	struct strlist *s;
	struct conf **confs=NULL;
	setup(&confs, NULL);
	build_file(CONFFILE, MIN_SERVER_CONF_NO_LISTEN
		"listen=0.0.0.0:1234\n"
		"listen=1.1.1.1:2345\n"
		"listen=9.8.7.6:3456\n"
		"max_children=12\n"
		"max_children=21\n");
	fail_unless(!conf_load_global_only(CONFFILE, confs));

	s=get_strlist(confs[OPT_LISTEN]);
	assert_strlist(&s, "0.0.0.0:1234", 12);
	assert_strlist(&s, "1.1.1.1:2345", 21);
	assert_strlist(&s, "9.8.7.6:3456", 21); // takes the previous as default
	fail_unless(get_strlist(confs[OPT_LISTEN_STATUS])==NULL);
	tear_down(NULL, &confs);
}
END_TEST

START_TEST(test_server_port_conf_complex)
{
	struct strlist *s;
	struct conf **confs=NULL;
	setup(&confs, NULL);
	build_file(CONFFILE, MIN_SERVER_CONF_NO_LISTEN
		"listen=0.0.0.0:1234\n"
		"listen=1.1.1.1:2345\n"
		"listen=9.8.7.6:3456\n"
		"max_children=12\n"
		"max_children=21\n"
		"max_children=37\n"
		"listen_status=::1:987\n"
		"listen_status=127.0.0.1:654\n"
		"listen_status=1abc:2323::9999:321\n"
		"max_status_children=4\n"
		"max_status_children=5\n"
		"max_status_children=6\n");
	fail_unless(!conf_load_global_only(CONFFILE, confs));

	s=get_strlist(confs[OPT_LISTEN]);
	assert_strlist(&s, "0.0.0.0:1234", 12);
	assert_strlist(&s, "1.1.1.1:2345", 21);
	assert_strlist(&s, "9.8.7.6:3456", 37);
	s=get_strlist(confs[OPT_LISTEN_STATUS]);
	assert_strlist(&s, "::1:987", 4);
	assert_strlist(&s, "127.0.0.1:654", 5);
	assert_strlist(&s, "1abc:2323::9999:321", 6);
	tear_down(NULL, &confs);
}
END_TEST

static void pre_post_assertions(struct conf **confs, const char *pre_path,
	const char *post_path, const char *pre_arg1, const char *pre_arg2,
	const char *post_arg1, const char *post_arg2,
	enum conf_opt o_script_pre, enum conf_opt o_script_post,
	enum conf_opt o_script_pre_arg, enum conf_opt o_script_post_arg,
	enum conf_opt o_script_pre_notify, enum conf_opt o_script_post_notify,
	enum conf_opt o_script_post_run_on_fail)
{
	struct strlist *s;
	ck_assert_str_eq(get_string(confs[o_script_pre]), pre_path);
	ck_assert_str_eq(get_string(confs[o_script_post]), post_path);
	s=get_strlist(confs[o_script_pre_arg]);
	assert_strlist(&s, pre_arg1, 0);
	assert_strlist(&s, pre_arg2, 0);
	assert_strlist(&s, NULL, 0);
	if(o_script_pre_notify!=OPT_MAX)
		fail_unless(get_int(confs[o_script_pre_notify])==1);
	s=get_strlist(confs[o_script_post_arg]);
	assert_strlist(&s, post_arg1, 0);
	assert_strlist(&s, post_arg2, 0);
	assert_strlist(&s, NULL, 0);
	if(o_script_post_notify!=OPT_MAX)
		fail_unless(get_int(confs[o_script_post_notify])==1);
	fail_unless(get_int(confs[o_script_post_run_on_fail])==1);
}

static void pre_post_checks(const char *buf, const char *pre_path,
	const char *post_path, const char *pre_arg1, const char *pre_arg2,
	const char *post_arg1, const char *post_arg2,
	enum conf_opt o_script_pre, enum conf_opt o_script_post,
	enum conf_opt o_script_pre_arg, enum conf_opt o_script_post_arg,
	enum conf_opt o_script_pre_notify, enum conf_opt o_script_post_notify,
	enum conf_opt o_script_post_run_on_fail)
{
	struct conf **confs=NULL;
	setup(&confs, NULL);
	build_file(CONFFILE, buf);
	fail_unless(!conf_load_global_only(CONFFILE, confs));
	pre_post_assertions(confs, pre_path, post_path, pre_arg1, pre_arg2,
		post_arg1, post_arg2,
		o_script_pre, o_script_post,
		o_script_pre_arg, o_script_post_arg,
		o_script_pre_notify, o_script_post_notify,
		o_script_post_run_on_fail);
	tear_down(NULL, &confs);
}

static void server_pre_post_checks(const char *buf, const char *pre_path,
	const char *post_path, const char *pre_arg1, const char *pre_arg2,
	const char *post_arg1, const char *post_arg2)
{
	pre_post_checks(buf, pre_path, post_path, pre_arg1, pre_arg2,
		post_arg1, post_arg2,
		OPT_S_SCRIPT_PRE, OPT_S_SCRIPT_POST,
		OPT_S_SCRIPT_PRE_ARG, OPT_S_SCRIPT_POST_ARG,
		OPT_S_SCRIPT_PRE_NOTIFY, OPT_S_SCRIPT_POST_NOTIFY,
		OPT_S_SCRIPT_POST_RUN_ON_FAIL);
}

#define SERVER_SCRIPT_PRE_POST 			\
	"server_script_pre=pre_path\n"		\
	"server_script_pre_arg=pre_arg1\n"	\
	"server_script_pre_arg=pre_arg2\n"	\
	"server_script_pre_notify=1\n"		\
	"server_script_post=post_path\n"	\
	"server_script_post_arg=post_arg1\n"	\
	"server_script_post_arg=post_arg2\n"	\
	"server_script_post_notify=1\n"		\
	"server_script_post_run_on_fail=1\n"	\

START_TEST(test_server_script_pre_post)
{
	const char *buf=MIN_SERVER_CONF SERVER_SCRIPT_PRE_POST;
	server_pre_post_checks(buf, "pre_path", "post_path", "pre_arg1",
		"pre_arg2", "post_arg1", "post_arg2");
}
END_TEST

#define SERVER_SCRIPT_CONF			\
	"server_script=path\n"			\
	"server_script_arg=arg1\n"		\
	"server_script_arg=arg2\n"		\
	"server_script_notify=1\n"		\
	"server_script_notify=1\n"		\
	"server_script_run_on_fail=1\n"		\
	"server_script_post_run_on_fail=1\n"	\

// Same as test_server_script_pre_post, but use server_script to set both pre
// and post at the same time.
START_TEST(test_server_script)
{
	const char *buf=MIN_SERVER_CONF SERVER_SCRIPT_CONF;
	server_pre_post_checks(buf, "path", "path", "arg1",
		"arg2", "arg1", "arg2");
}
END_TEST

static void backup_script_pre_post_checks(const char *buf, const char *pre_path,
	const char *post_path, const char *pre_arg1, const char *pre_arg2,
	const char *post_arg1, const char *post_arg2)
{
	pre_post_checks(buf, pre_path, post_path, pre_arg1, pre_arg2,
		post_arg1, post_arg2,
		OPT_B_SCRIPT_PRE, OPT_B_SCRIPT_POST,
		OPT_B_SCRIPT_PRE_ARG, OPT_B_SCRIPT_POST_ARG,
		OPT_MAX, OPT_MAX, OPT_B_SCRIPT_POST_RUN_ON_FAIL);
}

START_TEST(test_backup_script_pre_post)
{
	const char *buf=MIN_CLIENT_CONF
		"backup_script_pre=pre_path\n"
		"backup_script_pre_arg=pre_arg1\n"
		"backup_script_pre_arg=pre_arg2\n"
		"backup_script_post=post_path\n"
		"backup_script_post_arg=post_arg1\n"
		"backup_script_post_arg=post_arg2\n"
		"backup_script_post_run_on_fail=1\n"
	;
	backup_script_pre_post_checks(buf, "pre_path", "post_path", "pre_arg1",
		"pre_arg2", "post_arg1", "post_arg2");
}
END_TEST

// Same as test_backup_script_pre_post, but use backup_script to set both pre
// and post at the same time.
START_TEST(test_backup_script)
{
	const char *buf=MIN_CLIENT_CONF
		"backup_script=path\n"
		"backup_script_arg=arg1\n"
		"backup_script_arg=arg2\n"
		"backup_script_run_on_fail=1\n"
		"backup_script_post_run_on_fail=1\n"
	;
	backup_script_pre_post_checks(buf, "path", "path", "arg1",
		"arg2", "arg1", "arg2");
}
END_TEST

static void restore_script_pre_post_checks(const char *buf,
	const char *pre_path, const char *post_path,
	const char *pre_arg1, const char *pre_arg2,
	const char *post_arg1, const char *post_arg2)
{
	pre_post_checks(buf, pre_path, post_path, pre_arg1, pre_arg2,
		post_arg1, post_arg2,
		OPT_R_SCRIPT_PRE, OPT_R_SCRIPT_POST,
		OPT_R_SCRIPT_PRE_ARG, OPT_R_SCRIPT_POST_ARG,
		OPT_MAX, OPT_MAX, OPT_R_SCRIPT_POST_RUN_ON_FAIL);
}

START_TEST(test_restore_script_pre_post)
{
	const char *buf=MIN_CLIENT_CONF
		"restore_script_pre=pre_path\n"
		"restore_script_pre_arg=pre_arg1\n"
		"restore_script_pre_arg=pre_arg2\n"
		"restore_script_post=post_path\n"
		"restore_script_post_arg=post_arg1\n"
		"restore_script_post_arg=post_arg2\n"
		"restore_script_post_run_on_fail=1\n"
	;
	restore_script_pre_post_checks(buf, "pre_path", "post_path", "pre_arg1",
		"pre_arg2", "post_arg1", "post_arg2");
}
END_TEST

// Same as test_restore_script_pre_post, but use restore_script to set both pre
// and post at the same time.
START_TEST(test_restore_script)
{
	const char *buf=MIN_CLIENT_CONF
		"restore_script=path\n"
		"restore_script_arg=arg1\n"
		"restore_script_arg=arg2\n"
		"restore_script_run_on_fail=1\n"
		"restore_script_post_run_on_fail=1\n"
	;
	restore_script_pre_post_checks(buf, "path", "path", "arg1",
		"arg2", "arg1", "arg2");
}
END_TEST

static void clientconfdir_setup(struct conf ***globalcs, struct conf ***cconfs,
	const char *gbuf, const char *buf)
{
	const char *global_path=BASE "/burp-server.conf";
	setup(globalcs, cconfs);
	build_file(CONFFILE, gbuf);
	fail_unless(!conf_load_global_only(CONFFILE, *globalcs));
	set_string((*cconfs)[OPT_CNAME], "utestclient");
	build_file(global_path, buf);
	fail_unless(!conf_load_overrides(*globalcs, *cconfs, global_path));
	ck_assert_str_eq(get_string((*cconfs)[OPT_CNAME]), "utestclient");
}

#define NOTIFY_CONF				\
	"notify_success_script=/success_path\n"	\
	"notify_success_arg=/success/arg1\n"	\
	"notify_success_arg=/success/arg2\n"	\
	"notify_success_warnings_only=1\n"	\
	"notify_success_changes_only=1\n"	\
	"notify_failure_script=/failure_path\n"	\
	"notify_failure_arg=/failure/arg1\n"	\
	"notify_failure_arg=/failure/arg2\n"	\

static void notify_assertions(struct conf **cconfs)
{
	struct strlist *s;
	ck_assert_str_eq(get_string(cconfs[OPT_N_SUCCESS_SCRIPT]),
		"/success_path");
	s=get_strlist(cconfs[OPT_N_SUCCESS_ARG]);
	assert_strlist(&s, "/success/arg1", 0);
	assert_strlist(&s, "/success/arg2", 0);
	assert_include(&s, NULL);
	ck_assert_str_eq(get_string(cconfs[OPT_N_FAILURE_SCRIPT]),
		"/failure_path");
	fail_unless(get_int(cconfs[OPT_N_SUCCESS_WARNINGS_ONLY])==1);
	fail_unless(get_int(cconfs[OPT_N_SUCCESS_CHANGES_ONLY])==1);
	s=get_strlist(cconfs[OPT_N_FAILURE_ARG]);
	assert_strlist(&s, "/failure/arg1", 0);
	assert_strlist(&s, "/failure/arg2", 0);
	assert_include(&s, NULL);
}

#define MIN_CLIENTCONFDIR_BUF "# comment\n"

START_TEST(test_clientconfdir_conf)
{
	struct strlist *s;
	struct conf **globalcs=NULL;
	struct conf **cconfs=NULL;
	const char *gbuf=MIN_SERVER_CONF
		"restore_client=abc\n"
		"restore_client=xyz\n"
		"super_client=sss\n"
		"super_client=ttt\n"
		"timer_script=/timer/script\n"
		"timer_arg=/timer/arg1\n"
		"timer_arg=/timer/arg2\n"
		"label=qwe\n"
		"client_lockdir=/tmp/blah\n"
		NOTIFY_CONF
	;
	const char *buf=MIN_CLIENTCONFDIR_BUF
		"protocol=1\n"
		"directory=/another/dir\n"
		"directory_tree=0\n"
		"timestamp_format=%H %M %S\n"
		"password_check=0\n"
		"keep=4\n"
		"keep=7\n"
		"working_dir_recovery_method=resume\n"
		"max_resume_attempts=5\n"
		"librsync=0\n"
		"librsync_max_size=10Mb\n"
		"version_warn=0\n"
		"path_length_warn=0\n"
		"syslog=1\n"
		"client_can_delete=0\n"
		"client_can_force_backup=0\n"
		"client_can_list=0\n"
		"client_can_monitor=0\n"
		"client_can_restore=0\n"
		"client_can_verify=0\n"
		"restore_client=123\n"
		"restore_client=456\n"
		"super_client=ppp\n"
		"super_client=qqq\n"
		"dedup_group=dd_group\n"
		"label=rty\n"
		"label=xyz\n"
	;

	clientconfdir_setup(&globalcs, &cconfs, gbuf, buf);

	fail_unless(get_e_protocol(cconfs[OPT_PROTOCOL])==PROTO_1);
	ck_assert_str_eq(get_string(cconfs[OPT_DIRECTORY]), "/another/dir");
	fail_unless(get_int(cconfs[OPT_DIRECTORY_TREE])==0);
	ck_assert_str_eq(get_string(cconfs[OPT_TIMESTAMP_FORMAT]),
		"%H %M %S");
	fail_unless(get_int(cconfs[OPT_PASSWORD_CHECK])==0);
	s=get_strlist(cconfs[OPT_KEEP]);
	assert_strlist(&s, "4", 4);
	assert_strlist(&s, "7", 8); // The last one gets 1 added to it.
	assert_include(&s, NULL);
	s=get_strlist(cconfs[OPT_RESTORE_CLIENTS]);
	assert_strlist(&s, "123", 0);
	assert_strlist(&s, "456", 0);
	assert_strlist(&s, "abc", 0);
	assert_strlist(&s, "xyz", 0);
	assert_include(&s, NULL);
	s=get_strlist(cconfs[OPT_SUPER_CLIENTS]);
	assert_strlist(&s, "ppp", 0);
	assert_strlist(&s, "qqq", 0);
	assert_strlist(&s, "sss", 0);
	assert_strlist(&s, "ttt", 0);
	assert_include(&s, NULL);
	fail_unless(get_e_recovery_method(
	  cconfs[OPT_WORKING_DIR_RECOVERY_METHOD])==RECOVERY_METHOD_RESUME);
	fail_unless(get_int(cconfs[OPT_MAX_RESUME_ATTEMPTS])==5);
	fail_unless(get_int(cconfs[OPT_LIBRSYNC])==0);
	fail_unless(get_uint64_t(cconfs[OPT_LIBRSYNC_MAX_SIZE])==10485760);
	fail_unless(get_int(cconfs[OPT_VERSION_WARN])==0);
	fail_unless(get_int(cconfs[OPT_PATH_LENGTH_WARN])==0);
	fail_unless(get_int(cconfs[OPT_SYSLOG])==1);
	fail_unless(get_int(cconfs[OPT_CLIENT_CAN_DELETE])==0);
	fail_unless(get_int(cconfs[OPT_CLIENT_CAN_FORCE_BACKUP])==0);
	fail_unless(get_int(cconfs[OPT_CLIENT_CAN_LIST])==0);
	fail_unless(get_int(cconfs[OPT_CLIENT_CAN_RESTORE])==0);
	fail_unless(get_int(cconfs[OPT_CLIENT_CAN_VERIFY])==0);
	s=get_strlist(cconfs[OPT_TIMER_ARG]);
	assert_strlist(&s, "/timer/arg1", 0);
	assert_strlist(&s, "/timer/arg2", 0);
	assert_include(&s, NULL);
	ck_assert_str_eq(get_string(cconfs[OPT_DEDUP_GROUP]), "dd_group");
	s=get_strlist(cconfs[OPT_LABEL]);
	assert_strlist(&s, "rty", 0);
	assert_strlist(&s, "xyz", 0);
	notify_assertions(cconfs);
	ck_assert_str_eq(get_string(globalcs[OPT_CLIENT_LOCKDIR]), "/tmp/blah");
	ck_assert_str_eq(get_string(cconfs[OPT_CLIENT_LOCKDIR]), "/tmp/blah");
	tear_down(&globalcs, &cconfs);
}
END_TEST

START_TEST(test_clientconfdir_extra)
{
	struct strlist *s;
	struct conf **globalcs=NULL;
	struct conf **cconfs=NULL;
	const char *gbuf=MIN_SERVER_CONF
		"restore_client=abc\n"
		"include = /ignored/include\n"
		"timer_script = /ignored/timer\n"
		"timer_arg = /ignored/timer/arg1\n"
		"timer_arg = /ignored/timer/arg2\n"
		"notify_success_script = /ignored/success\n"
		"notify_success_arg = /ignored/success/arg\n"
		"notify_failure_script = /ignored/failure\n"
		"notify_failure_arg = /ignored/failure/arg\n"
		SERVER_SCRIPT_CONF
	;
	const char *buf=MIN_CLIENTCONFDIR_BUF
		"include = /testdir\n"
		"timer_script = /timer/script\n"
		"timer_arg = /timer/arg1\n"
		"timer_arg = /timer/arg2\n"
		SERVER_SCRIPT_PRE_POST
		NOTIFY_CONF
	;
	clientconfdir_setup(&globalcs, &cconfs, gbuf, buf);
	s=get_strlist(cconfs[OPT_RESTORE_CLIENTS]);
	assert_strlist(&s, "abc", 0);
	assert_include(&s, NULL);
	s=get_strlist(cconfs[OPT_INCLUDE]);
	assert_strlist(&s, "/testdir", 1);
	assert_include(&s, NULL);
	ck_assert_str_eq(get_string(cconfs[OPT_TIMER_SCRIPT]), "/timer/script");
	s=get_strlist(cconfs[OPT_TIMER_ARG]);
	assert_strlist(&s, "/timer/arg1", 0);
	assert_strlist(&s, "/timer/arg2", 0);
	assert_include(&s, NULL);
	pre_post_assertions(cconfs, "pre_path", "post_path",
		"pre_arg1", "pre_arg2",
		"post_arg1", "post_arg2",
		OPT_S_SCRIPT_PRE, OPT_S_SCRIPT_POST,
		OPT_S_SCRIPT_PRE_ARG, OPT_S_SCRIPT_POST_ARG,
		OPT_S_SCRIPT_PRE_NOTIFY, OPT_S_SCRIPT_POST_NOTIFY,
		OPT_S_SCRIPT_POST_RUN_ON_FAIL);
	notify_assertions(cconfs);
	tear_down(&globalcs, &cconfs);
}
END_TEST

START_TEST(test_strlist_reset)
{
	struct strlist *s;
	struct conf **confs=NULL;
	setup(&confs, NULL);
	build_file(CONFFILE, MIN_SERVER_CONF
		"timer_arg = /ignored/timer/arg1\n"
		"timer_arg = /ignored/timer/arg2\n"
		"timer_arg := /timer/arg3\n"
		"timer_arg = /timer/arg4\n");
	fail_unless(!conf_load_global_only(CONFFILE, confs));

	s=get_strlist(confs[OPT_TIMER_ARG]);
	assert_strlist(&s, "/timer/arg3", 0);
	assert_strlist(&s, "/timer/arg4", 0);
	assert_include(&s, NULL);
	tear_down(NULL, &confs);
}
END_TEST

START_TEST(test_clientconfdir_server_script)
{
	struct conf **globalcs=NULL;
	struct conf **cconfs=NULL;
	const char *gbuf=MIN_SERVER_CONF SERVER_SCRIPT_PRE_POST;
	const char *buf=MIN_CLIENTCONFDIR_BUF SERVER_SCRIPT_CONF;

	clientconfdir_setup(&globalcs, &cconfs, gbuf, buf);
	pre_post_assertions(cconfs, "path", "path",
		"arg1", "arg2",
		"arg1", "arg2",
		OPT_S_SCRIPT_PRE, OPT_S_SCRIPT_POST,
		OPT_S_SCRIPT_PRE_ARG, OPT_S_SCRIPT_POST_ARG,
		OPT_S_SCRIPT_PRE_NOTIFY, OPT_S_SCRIPT_POST_NOTIFY,
		OPT_S_SCRIPT_POST_RUN_ON_FAIL);
	tear_down(&globalcs, &cconfs);
}
END_TEST

static void switch_test(int expected_ret, const char *gbuf)
{
	char orig_client_conf[256]="";
	const char *clientconfdir;
	struct conf **globalcs=NULL;
	struct conf **cconfs=NULL;
	const char *buf=MIN_CLIENTCONFDIR_BUF;
	const char *orig_client_buf=MIN_CLIENTCONFDIR_BUF;

	clientconfdir_setup(&globalcs, &cconfs, gbuf, buf);
	clientconfdir=get_string(globalcs[OPT_CLIENTCONFDIR]);
	fail_unless(!recursive_delete(clientconfdir));
	snprintf(orig_client_conf, sizeof(orig_client_conf),
		"%s/orig_client", clientconfdir);
	build_file(orig_client_conf, orig_client_buf);
	fail_unless(conf_switch_to_orig_client(globalcs, cconfs,
		"orig_client")==expected_ret);
	if(!expected_ret)
	{
		ck_assert_str_eq(get_string(cconfs[OPT_CNAME]),
			"orig_client");
		ck_assert_str_eq(get_string(cconfs[OPT_SUPER_CLIENT]),
			"orig_client");
		ck_assert_str_eq(get_string(cconfs[OPT_ORIG_CLIENT]),
			"orig_client");
	}
	fail_unless(!recursive_delete(clientconfdir));
	tear_down(&globalcs, &cconfs);
}

START_TEST(test_conf_switch_to_orig_client_fail_restore_client)
{
	const char *gbuf=MIN_SERVER_CONF
		"restore_client=non-matching1\n"
		"restore_client=non-matching2\n";
	switch_test(-1, gbuf);
}
END_TEST

START_TEST(test_conf_switch_to_orig_client_ok_restore_client)
{
	const char *gbuf=MIN_SERVER_CONF
		"restore_client=non-matching1\n"
		"restore_client=utestclient\n";
	switch_test(0, gbuf);
}
END_TEST

struct cndata
{
	const char *cname;
	int valid;
};

static struct cndata c[] = {
	{ "testclient", 1 },
	{ "test.client", 1 },
	{ "testclient..", 1 },
	{ ".testclient", 0 },
	{ "testclient~", 0 },
	{ ".", 0 },
	{ "..", 0 },
	{ "/testclient", 0 },
	{ "test/client", 0 },
	{ "test\\client", 0 },
	{ "/..", 0 },
	{ "../", 0 },
	{ "../../testclient", 0 },
	{ "testclient/../blah", 0 },
};

START_TEST(test_cname_valid)
{
	FOREACH(c)
	{
		fail_unless(cname_valid(c[i].cname)==c[i].valid);
	}
}
END_TEST

START_TEST(test_conf_switch_to_orig_client_fail_super_client)
{
	const char *gbuf=MIN_SERVER_CONF
		"super_client=non-matching1\n"
		"super_client=non-matching2\n";
	switch_test(-1, gbuf);
}
END_TEST

START_TEST(test_conf_switch_to_orig_client_ok_super_client)
{
	const char *gbuf=MIN_SERVER_CONF
		"super_client=non-matching1\n"
		"super_client=utestclient\n";
	switch_test(0, gbuf);
}
END_TEST

struct client_can_data
{
	const char *config_str;
	int force_backup;
	int force_backup_orig;
	int force_backup_expected;
	int client_can;
	int client_can_orig;
	int client_can_expected;
};

static struct client_can_data ccd[] = {
	{ "super_client", 0, 0, 0,  0, 0, 0 },
	{ "super_client", 1, 0, 0,  1, 0, 1 },
	{ "super_client", 0, 1, 0,  0, 1, 0 },
	{ "super_client", 1, 1, 0,  1, 1, 1 },
	{ "restore_client", 0, 0, 0,  0, 0, 0 },
	{ "restore_client", 1, 0, 0,  1, 0, 0 },
	{ "restore_client", 0, 1, 0,  0, 1, 0 },
	{ "restore_client", 1, 1, 0,  1, 1, 1 },
};

START_TEST(test_conf_switch_to_orig_client_client_can)
{
	FOREACH(ccd)
	{
		char orig_client_conf[256]="";
		const char *clientconfdir;
		struct conf **globalcs=NULL;
		struct conf **cconfs=NULL;
		char buf[4096]="";
		char obuf[4096]="";
		char gbuf[4096]="";

		snprintf(gbuf, sizeof(gbuf), "%s%s=utestclient",
			MIN_SERVER_CONF, ccd[i].config_str);

		snprintf(buf, sizeof(buf), "%s\n"
			"client_can_force_backup=%d\n"
			"client_can_delete=%d\n"
			"client_can_diff=%d\n"
			"client_can_list=%d\n"
			"client_can_monitor=%d\n"
			"client_can_restore=%d\n"
			"client_can_verify=%d\n",
			MIN_SERVER_CONF,
			ccd[i].force_backup,
			ccd[i].client_can,
			ccd[i].client_can,
			ccd[i].client_can,
			ccd[i].client_can,
			ccd[i].client_can,
			ccd[i].client_can);
		snprintf(obuf, sizeof(obuf), "%s\n"
			"client_can_force_backup=%d\n"
			"client_can_delete=%d\n"
			"client_can_diff=%d\n"
			"client_can_list=%d\n"
			"client_can_monitor=%d\n"
			"client_can_restore=%d\n"
			"client_can_verify=%d\n",
			MIN_SERVER_CONF,
			ccd[i].force_backup_orig,
			ccd[i].client_can_orig,
			ccd[i].client_can_orig,
			ccd[i].client_can_orig,
			ccd[i].client_can_orig,
			ccd[i].client_can_orig,
			ccd[i].client_can_orig);

		clientconfdir_setup(&globalcs, &cconfs, gbuf, buf);
		clientconfdir=get_string(globalcs[OPT_CLIENTCONFDIR]);
		fail_unless(!recursive_delete(clientconfdir));
		snprintf(orig_client_conf, sizeof(orig_client_conf),
			"%s/orig_client", clientconfdir);
		build_file(orig_client_conf, obuf);
		fail_unless(conf_switch_to_orig_client(globalcs, cconfs,
			"orig_client")==0);

		fail_unless(get_int(cconfs[OPT_CLIENT_CAN_FORCE_BACKUP])
			==ccd[i].force_backup_expected);
		fail_unless(get_int(cconfs[OPT_CLIENT_CAN_DELETE])
			==ccd[i].client_can_expected);
		fail_unless(get_int(cconfs[OPT_CLIENT_CAN_DIFF])
			==ccd[i].client_can_expected);
		fail_unless(get_int(cconfs[OPT_CLIENT_CAN_LIST])
			==ccd[i].client_can_expected);
		fail_unless(get_int(cconfs[OPT_CLIENT_CAN_MONITOR])
			==ccd[i].client_can_expected);
		fail_unless(get_int(cconfs[OPT_CLIENT_CAN_RESTORE])
			==ccd[i].client_can_expected);
		fail_unless(get_int(cconfs[OPT_CLIENT_CAN_VERIFY])
			==ccd[i].client_can_expected);

		fail_unless(!recursive_delete(clientconfdir));
		tear_down(&globalcs, &cconfs);
	}
}
END_TEST

Suite *suite_conffile(void)
{
	Suite *s;
	TCase *tc_core;

	s=suite_create("conffile");

	tc_core=tcase_create("Core");

	tcase_add_test(tc_core, test_conf_get_pair);
	tcase_add_test(tc_core, test_client_conf);
	tcase_add_test(tc_core, test_client_conf_ca_conf_problems);
	tcase_add_test(tc_core, test_client_includes_excludes);
	tcase_add_test(tc_core, test_client_include_failures);
	tcase_add_test(tc_core, test_client_include_glob);
	tcase_add_test(tc_core, test_client_conf_monitor_exe);
	tcase_add_test(tc_core, test_client_conf_ports_opt_port_only);
	tcase_add_test(tc_core, test_client_conf_ports_opt_port_and_restore);
	tcase_add_test(tc_core, test_client_conf_ports_opt_port_and_all);
	tcase_add_test(tc_core, test_client_conf_ports_no_opt_port_and_all);
	tcase_add_test(tc_core, test_server_conf);
	tcase_add_test(tc_core, test_server_port_conf_one_max_child);
	tcase_add_test(tc_core, test_server_port_conf_too_many_max_child);
	tcase_add_test(tc_core, test_server_port_conf_few_max_child);
	tcase_add_test(tc_core, test_server_port_conf_complex);
	tcase_add_test(tc_core, test_server_script_pre_post);
	tcase_add_test(tc_core, test_server_script);
	tcase_add_test(tc_core, test_backup_script_pre_post);
	tcase_add_test(tc_core, test_backup_script);
	tcase_add_test(tc_core, test_restore_script_pre_post);
	tcase_add_test(tc_core, test_restore_script);
	tcase_add_test(tc_core, test_clientconfdir_conf);
	tcase_add_test(tc_core, test_clientconfdir_extra);
	tcase_add_test(tc_core, test_strlist_reset);
	tcase_add_test(tc_core, test_clientconfdir_server_script);
	tcase_add_test(tc_core, test_cname_valid);
	tcase_add_test(tc_core, test_conf_switch_to_orig_client_fail_restore_client);
	tcase_add_test(tc_core, test_conf_switch_to_orig_client_ok_restore_client);
	tcase_add_test(tc_core, test_conf_switch_to_orig_client_fail_super_client);
	tcase_add_test(tc_core, test_conf_switch_to_orig_client_ok_super_client);
	tcase_add_test(tc_core, test_conf_switch_to_orig_client_client_can);

	suite_add_tcase(s, tc_core);

	return s;
}
