#include <check.h>
#include <stdio.h>
#include <stdlib.h>
#include "../src/alloc.h"
#include "../src/conf.h"
#include "../src/conffile.h"

struct data
{
        const char *str;
	const char *field;
	const char *value;
};

static struct data d[] = {
	{ "a=b", "a", "b" },
	{ "a = b", "a", "b" },
	{ "   a  =    b ", "a", "b" },
	{ "   a  =    b \n", "a", "b" },
	{ "#a=b", NULL, NULL },
	{ "  #a=b", NULL, NULL },
	{ "a='b'", "a", "b" },
	{ "a='b", "a", "b" },
	{ "a=b'", "a", "b'" },
	{ "a=\"b\"", "a", "b" },
	{ "a=b\"", "a", "b\"" },
	{ "a=\"b", "a", "b" },
	{ "a=b # comment", "a", "b # comment" }, // Maybe fix this.
	{ "field=longvalue with spaces", "field", "longvalue with spaces" },
};

START_TEST(test_conf_get_pair)
{
        unsigned int i;
        for(i=0; i<sizeof(d)/sizeof(*d); i++)
	{
		char *field=NULL;
		char *value=NULL;
		char *str=strdup(d[i].str);
		conf_get_pair(str, &field, &value);
		if(!field || !d[i].field)
			ck_assert_int_eq(field==d[i].field, 1);
		else
			ck_assert_int_eq(!strcmp(field, d[i].field), 1);
		if(!value || !d[i].value)
			ck_assert_int_eq(value==d[i].value, 1);
		else
			ck_assert_int_eq(!strcmp(value, d[i].value), 1);
		free(str);
	}
}
END_TEST

#define MIN_CLIENT_CONF				\
	"mode=client\n"				\
	"server=4.5.6.7\n"			\
	"port=1234\n"				\
	"status_port=12345\n"			\
	"lockfile=/lockfile/path\n"		\
	"ssl_cert=/ssl/cert/path\n"		\
	"ssl_cert_ca=/cert_ca/path\n"		\
	"ssl_peer_cn=my_cn\n"			\
	"ca_csr_dir=/csr/dir\n"			\
	"ssl_key=/ssl/key/path\n"		\

START_TEST(test_client_conf)
{
	struct conf **confs;
	alloc_counters_reset();
	confs=confs_alloc();
	confs_init(confs);
	ck_assert_int_eq(conf_load_global_only_buf(MIN_CLIENT_CONF, confs), 0);
	ck_assert_str_eq(get_string(confs[OPT_SERVER]), "4.5.6.7");
	ck_assert_str_eq(get_string(confs[OPT_PORT]), "1234");
	ck_assert_str_eq(get_string(confs[OPT_STATUS_PORT]), "12345");
	ck_assert_str_eq(get_string(confs[OPT_LOCKFILE]), "/lockfile/path");
	ck_assert_str_eq(get_string(confs[OPT_SSL_CERT]), "/ssl/cert/path");
	ck_assert_str_eq(get_string(confs[OPT_SSL_CERT_CA]), "/cert_ca/path");
	ck_assert_str_eq(get_string(confs[OPT_SSL_PEER_CN]), "my_cn");
	ck_assert_str_eq(get_string(confs[OPT_SSL_KEY]), "/ssl/key/path");
	ck_assert_str_eq(get_string(confs[OPT_CA_CSR_DIR]), "/csr/dir");
	confs_free(&confs);
	ck_assert_int_eq(free_count, alloc_count);
}
END_TEST

START_TEST(test_client_includes)
{
	const char *buf=MIN_CLIENT_CONF
		"include=/a/b/c\n"
		"include=/x/y/z\n"
		"include=/r/s/t\n"
	;
	struct conf **confs;
	struct strlist *s;
	alloc_counters_reset();
	confs=confs_alloc();
	confs_init(confs);
	ck_assert_int_eq(conf_load_global_only_buf(buf, confs), 0);
	s=get_strlist(confs[OPT_INCLUDE]);
	ck_assert_str_eq(s->path, "/a/b/c"); s=s->next;
	ck_assert_str_eq(s->path, "/r/s/t"); s=s->next;
	ck_assert_str_eq(s->path, "/x/y/z"); s=s->next;
	ck_assert_int_eq(s==NULL, 1);
	confs_free(&confs);
	ck_assert_int_eq(free_count, alloc_count);
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
	tcase_add_test(tc_core, test_client_includes);
	suite_add_tcase(s, tc_core);

	return s;
}
