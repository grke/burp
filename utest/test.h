#ifndef __UTEST_H
#define __UTEST_H

#include "../src/conf.h"

#define ARR_LEN(array) (sizeof((array))/sizeof((array)[0]))
#define FOREACH(array) for(unsigned int i=0; i<ARR_LEN(array); i++)

#define MIN_SERVER_CONF				\
	"mode=server\n"				\
	"port=1234\n"				\
	"status_port=12345\n"			\
	"lockfile=/lockfile/path\n"		\
	"ssl_cert=/ssl/cert/path\n"		\
	"ssl_cert_ca=/cert_ca/path\n"		\
	"directory=/a/directory\n"		\
	"dedup_group=a_group\n"			\
	"clientconfdir=/a/ccdir\n"		\
	"ssl_dhfile=/a/dhfile\n"		\
	"keep=10\n"				\

extern int sub_ntests;

extern void alloc_check(void);
extern char **build_paths(int wanted);
extern struct sbuf *build_attribs(enum protocol protocol);
extern struct sbuf *build_attribs_reduce(enum protocol protocol);

Suite *suite_alloc(void);
Suite *suite_attribs(void);
Suite *suite_base64(void);
Suite *suite_cmd(void);
Suite *suite_conf(void);
Suite *suite_conffile(void);
Suite *suite_fzp(void);
Suite *suite_hexmap(void);
Suite *suite_lock(void);
Suite *suite_pathcmp(void);
Suite *suite_server_sdirs(void);
Suite *suite_server_protocol1_dpth(void);
Suite *suite_server_protocol1_fdirs(void);
Suite *suite_server_protocol2_dpth(void);
Suite *suite_sbuf(void);

#endif
