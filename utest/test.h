#ifndef __UTEST_H
#define __UTEST_H

#include "../src/burp.h"
#include "../src/conf.h"
#include <check.h>

#define ARR_LEN(array) (sizeof((array))/sizeof((array)[0]))
#define FOREACH(array) for(unsigned int i=0; i<ARR_LEN(array); i++)

#define MIN_SERVER_CONF_NO_LISTEN		\
	"mode=server\n"				\
	"lockfile=/lockfile/path\n"		\
	"ssl_cert=/ssl/cert/path\n"		\
	"ssl_cert_ca=/cert_ca/path\n"		\
	"directory=/a/directory\n"		\
	"dedup_group=a_group\n"			\
	"clientconfdir=clientconfdir\n"		\
	"ssl_dhfile=/a/dhfile\n"		\
	"keep=10\n"				\

#define MIN_SERVER_CONF				\
	MIN_SERVER_CONF_NO_LISTEN		\
	"listen=0.0.0.0:1234\n"			\
	"listen_status=0.0.0.0:12345\n"		\

#define MIN_CLIENT_CONF_NO_PORTS		\
	"mode=client\n"				\
	"server=4.5.6.7\n"			\
	"lockfile=/lockfile/path\n"		\
	"ssl_cert=/ssl/cert/path\n"		\
	"ssl_cert_ca=/cert_ca/path\n"		\
	"ssl_peer_cn=my_cn\n"			\
	"ca_csr_dir=/csr/dir\n"			\
	"ssl_key=/ssl/key/path\n"		\

#define MIN_CLIENT_CONF				\
	MIN_CLIENT_CONF_NO_PORTS		\
	"port=1234\n"				\
	"status_port=12345\n"			\

struct iobuf;
struct sbuf;
struct sd;
struct sdirs;

extern int sub_ntests;

extern void alloc_check_init(void);
extern void alloc_check(void);

extern void assert_iobuf(struct iobuf *a, struct iobuf *b);
extern void assert_sbuf(struct sbuf *a, struct sbuf *b);
extern struct manio *do_manio_open(const char *path, const char *mode,
	int phase);
extern void assert_bu_list(struct sdirs *sdirs, struct sd *s, unsigned int len);
extern void assert_files_equal(const char *opath, const char *npath);
extern void assert_files_compressed_equal(const char *opath, const char *npath);
extern void assert_xattr(const char *expected,
	const char *retrieved, size_t rlen);


Suite *suite_alloc(void);
Suite *suite_asfd(void);
Suite *suite_attribs(void);
Suite *suite_base64(void);
Suite *suite_client_acl(void);
Suite *suite_client_auth(void);
Suite *suite_client_delete(void);
Suite *suite_client_extra_comms(void);
Suite *suite_client_extrameta(void);
Suite *suite_client_find(void);
Suite *suite_client_monitor(void);
Suite *suite_client_monitor_json_input(void);
Suite *suite_client_monitor_lline(void);
Suite *suite_client_monitor_status_client_ncurses(void);
Suite *suite_client_protocol1_backup_phase2(void);
Suite *suite_client_restore(void);
Suite *suite_client_xattr(void);
Suite *suite_cmd(void);
Suite *suite_cntr(void);
Suite *suite_conf(void);
Suite *suite_conffile(void);
Suite *suite_fzp(void);
Suite *suite_hexmap(void);
Suite *suite_lock(void);
Suite *suite_pathcmp(void);
Suite *suite_protocol1_handy(void);
Suite *suite_protocol1_rs_buf(void);
Suite *suite_server_auth(void);
Suite *suite_server_autoupgrade(void);
Suite *suite_server_ca(void);
Suite *suite_server_backup_phase3(void);
Suite *suite_server_bu_get(void);
Suite *suite_server_delete(void);
Suite *suite_server_extra_comms(void);
Suite *suite_server_list(void);
Suite *suite_server_manio(void);
Suite *suite_server_monitor_browse(void);
Suite *suite_server_monitor_cache(void);
Suite *suite_server_monitor_cstat(void);
Suite *suite_server_monitor_json_output(void);
Suite *suite_server_monitor_status_server(void);
Suite *suite_server_resume(void);
Suite *suite_server_restore(void);
Suite *suite_server_run_action(void);
Suite *suite_server_sdirs(void);
Suite *suite_server_timer(void);
Suite *suite_server_protocol1_backup_phase2(void);
Suite *suite_server_protocol1_backup_phase4(void);
Suite *suite_server_protocol1_bedup(void);
Suite *suite_server_protocol1_blocklen(void);
Suite *suite_server_protocol1_dpth(void);
Suite *suite_server_protocol1_fdirs(void);
Suite *suite_server_protocol1_restore(void);
Suite *suite_slist(void);
Suite *suite_times(void);

#endif
