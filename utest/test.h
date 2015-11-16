#ifndef __UTEST_H
#define __UTEST_H

#include "../src/burp.h"
#include "../src/conf.h"
#include <check.h>

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
	"clientconfdir=clientconfdir\n"		\
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
extern void assert_bu_list(struct sdirs *sdirs, struct sd *s, unsigned int len);

Suite *suite_alloc(void);
Suite *suite_attribs(void);
Suite *suite_base64(void);
Suite *suite_client_auth(void);
Suite *suite_client_find(void);
Suite *suite_client_monitor_json_input(void);
Suite *suite_client_monitor_lline(void);
Suite *suite_client_protocol1_backup_phase2(void);
Suite *suite_client_protocol2_backup_phase2(void);
Suite *suite_client_restore(void);
Suite *suite_client_xattr(void);
Suite *suite_cmd(void);
Suite *suite_conf(void);
Suite *suite_conffile(void);
Suite *suite_fzp(void);
Suite *suite_hexmap(void);
Suite *suite_lock(void);
Suite *suite_pathcmp(void);
Suite *suite_protocol1_rs_buf(void);
Suite *suite_protocol2_blist(void);
Suite *suite_protocol2_rabin_rconf(void);
Suite *suite_protocol2_rabin_win(void);
Suite *suite_server_bu_get(void);
Suite *suite_server_delete(void);
Suite *suite_server_list(void);
Suite *suite_server_manio(void);
Suite *suite_server_monitor_browse(void);
Suite *suite_server_monitor_cstat(void);
Suite *suite_server_resume(void);
Suite *suite_server_sdirs(void);
Suite *suite_server_protocol1_bedup(void);
Suite *suite_server_protocol1_blocklen(void);
Suite *suite_server_protocol1_dpth(void);
Suite *suite_server_protocol1_fdirs(void);
Suite *suite_server_protocol2_backup_phase4(void);
Suite *suite_server_protocol2_champ_chooser_candidate(void);
Suite *suite_server_protocol2_champ_chooser_dindex(void);
Suite *suite_server_protocol2_champ_chooser_scores(void);
Suite *suite_server_protocol2_champ_chooser_sparse(void);
Suite *suite_server_protocol2_dpth(void);

#endif
