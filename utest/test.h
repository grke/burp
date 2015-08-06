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

extern int sub_ntests;

extern void alloc_check(void);

extern void assert_iobuf(struct iobuf *a, struct iobuf *b);
extern void assert_sbuf(struct sbuf *a, struct sbuf *b, enum protocol protocol);
extern struct manio *do_manio_open(const char *path, const char *mode,
	enum protocol protocol, int phase);

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
Suite *suite_protocol2_blist(void);
Suite *suite_protocol2_rabin_rconf(void);
Suite *suite_protocol2_rabin_win(void);
Suite *suite_client_find(void);
Suite *suite_server_manio(void);
Suite *suite_server_resume(void);
Suite *suite_server_sdirs(void);
Suite *suite_server_protocol1_dpth(void);
Suite *suite_server_protocol1_fdirs(void);
Suite *suite_server_protocol2_backup_phase4(void);
Suite *suite_server_protocol2_champ_chooser_candidate(void);
Suite *suite_server_protocol2_champ_chooser_scores(void);
Suite *suite_server_protocol2_champ_chooser_sparse(void);
Suite *suite_server_protocol2_dpth(void);

#endif
