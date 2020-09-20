#include "burp.h"
#include "strlist.h"
#include "conf.h"
#include "log.h"
#include "alloc.h"
#include "cntr.h"
#include "prepend.h"
#include "server/dpth.h"

#include <assert.h>

enum burp_mode str_to_burp_mode(const char *str)
{
	if(!strcmp(str, "server"))
		return BURP_MODE_SERVER;
	else if(!strcmp(str, "client"))
		return BURP_MODE_CLIENT;
	logp("Unknown mode setting: %s\n", str);
	return BURP_MODE_UNSET;
}

static const char *burp_mode_to_str(enum burp_mode bm)
{
	switch(bm)
	{
		case BURP_MODE_UNSET: return "unset";
		case BURP_MODE_SERVER: return "server";
		case BURP_MODE_CLIENT: return "client";
		default: return "unknown";
	}
}

enum recovery_method str_to_recovery_method(const char *str)
{
	if(!strcmp(str, "delete"))
		return RECOVERY_METHOD_DELETE;
	else if(!strcmp(str, "resume"))
		return RECOVERY_METHOD_RESUME;
	logp("Unknown working_dir_recovery_method setting: %s\n", str);
	return RECOVERY_METHOD_UNSET;
}

const char *recovery_method_to_str(enum recovery_method r)
{
	switch(r)
	{
		case RECOVERY_METHOD_DELETE: return "delete";
		case RECOVERY_METHOD_RESUME: return "resume";
		default: return "unknown";
	}
}

const char *rshash_to_str(enum rshash r)
{
	switch(r)
	{
		case RSHASH_UNSET: return "unset";
		case RSHASH_MD4: return "md4";
		case RSHASH_BLAKE2: return "blake2";
		default: return "unknown";
	}
}

enum protocol str_to_protocol(const char *str)
{
	if(!strcmp(str, "0"))
		return PROTO_AUTO;
	else if(!strcmp(str, "1"))
		return PROTO_1;
	else if(!strcmp(str, "2"))
		return PROTO_2;
	logp("Unknown protocol setting: %s\n", str);
	return PROTO_AUTO;
}

struct strlist *get_strlist(struct conf *conf)
{
	assert(conf->conf_type==CT_STRLIST);
	return conf->data.sl;
}

char *get_string(struct conf *conf)
{
	assert(conf->conf_type==CT_STRING);
	return conf->data.s;
}

int get_int(struct conf *conf)
{
	assert(conf->conf_type==CT_UINT);
	return conf->data.i;
}

uint64_t get_uint64_t(struct conf *conf)
{
	assert(conf->conf_type==CT_SSIZE_T);
	return conf->data.uint64;
}

float get_float(struct conf *conf)
{
	assert(conf->conf_type==CT_FLOAT);
	return conf->data.f;
}

mode_t get_mode_t(struct conf *conf)
{
	assert(conf->conf_type==CT_MODE_T);
	return conf->data.mode;
}

enum burp_mode get_e_burp_mode(struct conf *conf)
{
	assert(conf->conf_type==CT_E_BURP_MODE);
	return conf->data.burp_mode;
}

enum protocol get_e_protocol(struct conf *conf)
{
	assert(conf->conf_type==CT_E_PROTOCOL);
	return conf->data.protocol;
}

enum protocol get_protocol(struct conf **confs)
{
	return get_e_protocol(confs[OPT_PROTOCOL]);
}

enum recovery_method get_e_recovery_method(struct conf *conf)
{
	assert(conf->conf_type==CT_E_RECOVERY_METHOD);
	return conf->data.recovery_method;
}

enum rshash get_e_rshash(struct conf *conf)
{
	assert(conf->conf_type==CT_E_RSHASH);
	return conf->data.rshash;
}

struct cntr *get_cntr(struct conf **confs)
{
	return confs[OPT_CNTR]->data.cntr;
}

int set_string(struct conf *conf, const char *s)
{
	assert(conf->conf_type==CT_STRING);
	if(conf->data.s) free_w(&(conf->data.s));
	if(s && !(conf->data.s=strdup_w(s, __func__)))
		return -1;
	return 0;
}

int set_int(struct conf *conf, unsigned int i)
{
	assert(conf->conf_type==CT_UINT);
	conf->data.i=i;
	return 0;
}

int set_strlist(struct conf *conf, struct strlist *s)
{
	assert(conf->conf_type==CT_STRLIST);
	if(conf->data.sl) strlists_free(&conf->data.sl);
	conf->data.sl=s;
	return 0;
}

int set_float(struct conf *conf, float f)
{
	assert(conf->conf_type==CT_FLOAT);
	conf->data.f=f;
	return 0;
}

int set_e_burp_mode(struct conf *conf, enum burp_mode bm)
{
	assert(conf->conf_type==CT_E_BURP_MODE);
	conf->data.burp_mode=bm;
	return 0;
}

int set_e_protocol(struct conf *conf, enum protocol p)
{
	assert(conf->conf_type==CT_E_PROTOCOL);
	conf->data.protocol=p;
	return 0;
}

int set_protocol(struct conf **confs, enum protocol p)
{
	return set_e_protocol(confs[OPT_PROTOCOL], p);
}

int set_e_recovery_method(struct conf *conf, enum recovery_method r)
{
	assert(conf->conf_type==CT_E_RECOVERY_METHOD);
	conf->data.recovery_method=r;
	return 0;
}

int set_e_rshash(struct conf *conf, enum rshash r)
{
	assert(conf->conf_type==CT_E_RSHASH);
	conf->data.rshash=r;
	return 0;
}

int set_mode_t(struct conf *conf, mode_t m)
{
	assert(conf->conf_type==CT_MODE_T);
	conf->data.mode=m;
	return 0;
}

int set_uint64_t(struct conf *conf, uint64_t s)
{
	assert(conf->conf_type==CT_SSIZE_T);
	conf->data.uint64=s;
	return 0;
}

int set_cntr(struct conf *conf, struct cntr *cntr)
{
	assert(conf->conf_type==CT_CNTR);
	conf->data.cntr=cntr;
	return 0;
}

int add_to_strlist(struct conf *conf, const char *value, int include)
{
	assert(conf->conf_type==CT_STRLIST);
	if(conf->flags & CONF_FLAG_STRLIST_SORTED)
		return strlist_add_sorted(&(conf->data.sl), value, include);
	else
		return strlist_add(&(conf->data.sl), value, include);
}

int add_to_strlist_include_uniq(struct conf *conf, const char *value)
{
	return strlist_add_sorted_uniq(&(conf->data.sl), value, 1);
}

void conf_free_content(struct conf *c)
{
	if(!c) return;
	switch(c->conf_type)
	{
		case CT_STRING:
			free_w(&c->data.s);
			break;
		case CT_STRLIST:
			strlists_free(&c->data.sl);
			break;
		case CT_CNTR:
			cntr_free(&c->data.cntr);
			break;
		case CT_FLOAT:
		case CT_E_BURP_MODE:
		case CT_E_PROTOCOL:
		case CT_E_RECOVERY_METHOD:
		case CT_E_RSHASH:
		case CT_UINT:
		case CT_MODE_T:
		case CT_SSIZE_T:
			memset(&c->data, 0, sizeof(c->data));
			break;
	}
}

void confs_memcpy(struct conf **dst, struct conf **src)
{
	int i=0;
	for(i=0; i<OPT_MAX; i++)
	{
		free_v((void **)&(dst[i]));
		dst[i]=src[i];
	}
}

void confs_null(struct conf **confs)
{
	int i=0;
	if(!confs) return;
	for(i=0; i<OPT_MAX; i++) confs[i]=NULL;
}

void confs_free_content(struct conf **confs)
{
	int i=0;
	if(!confs) return;
	for(i=0; i<OPT_MAX; i++) conf_free_content(confs[i]);
}

/* Free only stuff related to includes/excludes.
   This is so that the server can override them all on the client. */
void free_incexcs(struct conf **confs)
{
	int i=0;
	if(!confs) return;
	for(i=0; i<OPT_MAX; i++)
		if(confs[i]->flags & CONF_FLAG_INCEXC)
			conf_free_content(confs[i]);
}

static void sc(struct conf *conf, uint8_t flags,
	enum conf_type conf_type, const char *field)
{
	conf->conf_type=conf_type;
	conf->field=field;
	conf->flags=flags;
	memset(&conf->data, 0, sizeof(conf->data));
}

static int sc_str(struct conf *conf, const char *def,
	uint8_t flags, const char *field)
{
	sc(conf, flags, CT_STRING, field);
	return set_string(conf, def);
}

static int sc_int(struct conf *conf, unsigned int def,
	uint8_t flags, const char *field)
{
	sc(conf, flags, CT_UINT, field);
	return set_int(conf, def);
}

static int sc_lst(struct conf *conf, struct strlist *def,
	uint8_t flags, const char *field)
{
	sc(conf, flags, CT_STRLIST, field);
	return set_strlist(conf, def);
}

static int sc_flt(struct conf *conf, float def,
	uint8_t flags, const char *field)
{
	sc(conf, flags, CT_FLOAT, field);
	return set_float(conf, def);
}

static int sc_ebm(struct conf *conf, enum burp_mode def,
	uint8_t flags, const char *field)
{
	sc(conf, flags, CT_E_BURP_MODE, field);
	return set_e_burp_mode(conf, def);
}

static int sc_epr(struct conf *conf, enum protocol def,
	uint8_t flags, const char *field)
{
	sc(conf, flags, CT_E_PROTOCOL, field);
	return set_e_protocol(conf, def);
}

static int sc_rec(struct conf *conf, enum recovery_method def,
	uint8_t flags, const char *field)
{
	sc(conf, flags, CT_E_RECOVERY_METHOD, field);
	return set_e_recovery_method(conf, def);
}

static int sc_rsh(struct conf *conf, enum rshash def,
	uint8_t flags, const char *field)
{
	sc(conf, flags, CT_E_RSHASH, field);
	return set_e_rshash(conf, def);
}

static int sc_mod(struct conf *conf, mode_t def,
	uint8_t flags, const char *field)
{
	sc(conf, flags, CT_MODE_T, field);
	return set_mode_t(conf, def);
}

static int sc_u64(struct conf *conf, uint64_t def,
	uint8_t flags, const char *field)
{
	sc(conf, flags, CT_SSIZE_T, field);
	return set_uint64_t(conf, def);
}

static int sc_cntr(struct conf *conf, struct cntr *def,
	uint8_t flags, const char *field)
{
	sc(conf, flags, CT_CNTR, field);
	return set_cntr(conf, def);
}

static int reset_conf(struct conf **c, enum conf_opt o)
{
	// Do this with a switch statement, so that we get compiler warnings
	// if anything is missed.
	switch(o)
	{
	case OPT_BURP_MODE:
	  return sc_ebm(c[o], BURP_MODE_UNSET, 0, "mode");
	case OPT_LOCKFILE:
	  return sc_str(c[o], 0, 0, "lockfile");
	case OPT_PIDFILE:
	  return sc_str(c[o], 0, 0, "pidfile");
	case OPT_SSL_CERT_CA:
	  return sc_str(c[o], 0, 0, "ssl_cert_ca");
	case OPT_SSL_CERT:
	  return sc_str(c[o], 0, 0, "ssl_cert");
	case OPT_SSL_KEY:
	  return sc_str(c[o], 0, 0, "ssl_key");
	case OPT_SSL_KEY_PASSWORD:
	  // FIX THIS: synonym: ssl_cert_password
	  return sc_str(c[o], 0, 0, "ssl_key_password");
	case OPT_SSL_PEER_CN:
	  return sc_str(c[o], 0, 0, "ssl_peer_cn");
	case OPT_SSL_CIPHERS:
	  return sc_str(c[o], 0, 0, "ssl_ciphers");
	case OPT_SSL_COMPRESSION:
	  return sc_int(c[o], 5, 0, "ssl_compression");
	case OPT_SSL_VERIFY_PEER_EARLY:
	  return sc_int(c[o], 0, 0, "ssl_verify_peer_early");
	case OPT_RATELIMIT:
	  return sc_flt(c[o], 0, 0, "ratelimit");
	case OPT_NETWORK_TIMEOUT:
	  return sc_int(c[o], 60*60*2, 0, "network_timeout");
	case OPT_CLIENT_IS_WINDOWS:
	  return sc_int(c[o], 0, 0, "client_is_windows");
	case OPT_PEER_VERSION:
	  return sc_str(c[o], 0, 0, "peer_version");
	case OPT_PORT:
	  return sc_lst(c[o], 0, 0, "port");
	case OPT_STATUS_PORT:
	  return sc_lst(c[o], 0, 0, "status_port");
	case OPT_LISTEN:
	  return sc_lst(c[o], 0, 0, "listen");
	case OPT_LISTEN_STATUS:
	  return sc_lst(c[o], 0, 0, "listen_status");
	case OPT_PORT_BACKUP:
	  return sc_int(c[o], 0, 0, "port_backup");
	case OPT_PORT_RESTORE:
	  return sc_int(c[o], 0, 0, "port_restore");
	case OPT_PORT_VERIFY:
	  return sc_int(c[o], 0, 0, "port_verify");
	case OPT_PORT_LIST:
	  return sc_int(c[o], 0, 0, "port_list");
	case OPT_PORT_DELETE:
	  return sc_int(c[o], 0, 0, "port_delete");
	case OPT_SSL_DHFILE:
	  return sc_str(c[o], 0, 0, "ssl_dhfile");
	case OPT_MAX_CHILDREN:
	  return sc_lst(c[o], 0, 0, "max_children");
	case OPT_MAX_STATUS_CHILDREN:
	  return sc_lst(c[o], 0, 0, "max_status_children");
	case OPT_MAX_PARALLEL_BACKUPS:
	  return sc_int(c[o], 0, CONF_FLAG_CC_OVERRIDE, "max_parallel_backups");
	case OPT_CLIENT_LOCKDIR:
	  return sc_str(c[o], 0, CONF_FLAG_CC_OVERRIDE, "client_lockdir");
	case OPT_UMASK:
	  return sc_mod(c[o], 0022, 0, "umask");
	case OPT_MAX_HARDLINKS:
	  return sc_int(c[o], 10000, 0, "max_hardlinks");
	case OPT_MAX_STORAGE_SUBDIRS:
	  return sc_int(c[o], MAX_STORAGE_SUBDIRS, 0, "max_storage_subdirs");
	case OPT_DAEMON:
	  return sc_int(c[o], 1, 0, "daemon");
	case OPT_CA_CONF:
	  return sc_str(c[o], 0, 0, "ca_conf");
	case OPT_CA_NAME:
	  return sc_str(c[o], 0, 0, "ca_name");
	case OPT_CA_SERVER_NAME:
	  return sc_str(c[o], 0, 0, "ca_server_name");
	case OPT_CA_BURP_CA:
	  return sc_str(c[o], 0, 0, "ca_" PACKAGE_TARNAME "_ca");
        case OPT_CA_CRL:
          return sc_str(c[o], 0, 0, "ca_crl");
        case OPT_CA_CRL_CHECK:
          return sc_int(c[o], 0, 0, "ca_crl_check");
	case OPT_RBLK_MEMORY_MAX:
	  return sc_u64(c[o], 256*1024*1024, // 256 Mb.
		CONF_FLAG_CC_OVERRIDE, "rblk_memory_max");
	case OPT_SPARSE_SIZE_MAX:
	  return sc_u64(c[o], 256*1024*1024, // 256 Mb.
		CONF_FLAG_CC_OVERRIDE, "sparse_size_max");
	case OPT_MONITOR_LOGFILE:
	  return sc_str(c[o], 0, 0, "monitor_logfile");
	case OPT_MONITOR_EXE:
	  return sc_str(c[o], 0, 0, "monitor_exe");
	case OPT_BACKUP_FAILOVERS_LEFT:
	  return sc_int(c[o], 0, 0, "");
	case OPT_CNAME:
	  return sc_str(c[o], 0, 0, "cname");
	case OPT_CNAME_LOWERCASE:
	  return sc_int(c[o], 0, 0, "cname_lowercase");
	case OPT_CNAME_FQDN:
	  return sc_int(c[o], 1, 0, "cname_fqdn");
	case OPT_PASSWORD:
	  return sc_str(c[o], 0, 0, "password");
	case OPT_PASSWD:
	  return sc_str(c[o], 0, 0, "passwd");
	case OPT_SERVER:
	  return sc_str(c[o], 0, 0, "server");
	case OPT_SERVER_FAILOVER:
	  return sc_lst(c[o], 0, 0, "server_failover");
	case OPT_FAILOVER_ON_BACKUP_ERROR:
	  return sc_int(c[o], 0, 0, "failover_on_backup_error");
	case OPT_ENCRYPTION_PASSWORD:
	  return sc_str(c[o], 0, 0, "encryption_password");
	case OPT_AUTOUPGRADE_OS:
	  return sc_str(c[o], 0, 0, "autoupgrade_os");
	case OPT_AUTOUPGRADE_DIR:
	  return sc_str(c[o], 0, 0, "autoupgrade_dir");
	case OPT_CA_CSR_DIR:
	  return sc_str(c[o], 0, 0, "ca_csr_dir");
	case OPT_RANDOMISE:
	  return sc_int(c[o], 0, 0, "randomise");
	case OPT_RESTORE_LIST:
	  return sc_str(c[o], 0, 0, "restore_list");
	case OPT_ENABLED:
	  return sc_int(c[o], 1, CONF_FLAG_CC_OVERRIDE, "enabled");
	case OPT_SERVER_CAN_OVERRIDE_INCLUDES:
	  return sc_int(c[o], 1, 0, "server_can_override_includes");
	case OPT_BACKUP:
	  return sc_str(c[o], 0, CONF_FLAG_INCEXC_RESTORE, "backup");
	case OPT_BACKUP2:
	  return sc_str(c[o], 0, 0, "backup2");
	case OPT_RESTOREPREFIX:
	  return sc_str(c[o], 0, CONF_FLAG_INCEXC_RESTORE, "restoreprefix");
	case OPT_STRIP_FROM_PATH:
	  return sc_str(c[o], 0, CONF_FLAG_INCEXC_RESTORE, "stripfrompath");
	case OPT_BROWSEFILE:
	  return sc_str(c[o], 0, 0, "browsefile");
	case OPT_BROWSEDIR:
	  return sc_str(c[o], 0, 0, "browsedir");
	case OPT_GLOB_AFTER_SCRIPT_PRE:
	  return sc_int(c[o], 1, 0, "glob_after_script_pre");
	case OPT_B_SCRIPT_PRE:
	  return sc_str(c[o], 0, 0, "backup_script_pre");
	case OPT_B_SCRIPT_PRE_ARG:
	  return sc_lst(c[o], 0, 0, "backup_script_pre_arg");
	case OPT_B_SCRIPT_POST:
	  return sc_str(c[o], 0, 0, "backup_script_post");
	case OPT_B_SCRIPT_POST_ARG:
	  return sc_lst(c[o], 0, 0, "backup_script_post_arg");
	case OPT_B_SCRIPT_POST_RUN_ON_FAIL:
	  return sc_int(c[o], 0, 0, "backup_script_post_run_on_fail");
	case OPT_B_SCRIPT_RESERVED_ARGS:
	  return sc_int(c[o], 1, 0, "backup_script_reserved_args");
	case OPT_R_SCRIPT_PRE:
	  return sc_str(c[o], 0, 0, "restore_script_pre");
	case OPT_R_SCRIPT_PRE_ARG:
	  return sc_lst(c[o], 0, 0, "restore_script_pre_arg");
	case OPT_R_SCRIPT_POST:
	  return sc_str(c[o], 0, 0, "restore_script_post");
	case OPT_R_SCRIPT_POST_ARG:
	  return sc_lst(c[o], 0, 0, "restore_script_post_arg");
	case OPT_R_SCRIPT_POST_RUN_ON_FAIL:
	  return sc_int(c[o], 0, 0, "restore_script_post_run_on_fail");
	case OPT_B_SCRIPT:
	  return sc_str(c[o], 0, 0, "backup_script");
	case OPT_B_SCRIPT_ARG:
	  return sc_lst(c[o], 0, 0, "backup_script_arg");
	case OPT_R_SCRIPT:
	  return sc_str(c[o], 0, 0, "restore_script");
	case OPT_R_SCRIPT_ARG:
	  return sc_lst(c[o], 0, 0, "restore_script_arg");
	case OPT_R_SCRIPT_RESERVED_ARGS:
	  return sc_int(c[o], 1, 0, "restore_script_reserved_args");
	case OPT_SEND_CLIENT_CNTR:
	  return sc_int(c[o], 0, 0, "send_client_cntr");
	case OPT_SUPER_CLIENT:
	  return sc_str(c[o], 0, 0, "");
	case OPT_RESTORE_PATH:
	  return sc_str(c[o], 0, 0, "restore_path");
	case OPT_ORIG_CLIENT:
	  return sc_str(c[o], 0, CONF_FLAG_INCEXC_RESTORE, "orig_client");
	case OPT_CONNECT_CLIENT:
	  return sc_str(c[o], 0, 0, "");
	case OPT_CNTR:
	  return sc_cntr(c[o], 0, 0, "");
	case OPT_VSS_RESTORE:
	  return sc_int(c[o], VSS_RESTORE_ON, 0, "");
	case OPT_READALL:
	  return sc_int(c[o], 0, CONF_FLAG_CC_OVERRIDE, "readall");
	case OPT_BREAKPOINT:
	  return sc_int(c[o], 0,
		CONF_FLAG_CC_OVERRIDE, "breakpoint");
	case OPT_CONFFILE:
	  return sc_str(c[o], 0,
		CONF_FLAG_CC_OVERRIDE, "conffile");
	case OPT_SYSLOG:
	  return sc_int(c[o], 0,
		CONF_FLAG_CC_OVERRIDE, "syslog");
	case OPT_STDOUT:
	  return sc_int(c[o], 1,
		CONF_FLAG_CC_OVERRIDE, "stdout");
	case OPT_PROGRESS_COUNTER:
	  return sc_int(c[o], 0,
		CONF_FLAG_CC_OVERRIDE, "progress_counter");
	case OPT_USER:
	  return sc_str(c[o], 0,
		CONF_FLAG_CC_OVERRIDE, "user");
	case OPT_GROUP:
	  return sc_str(c[o], 0,
		CONF_FLAG_CC_OVERRIDE, "group");
	case OPT_PROTOCOL:
	  return sc_epr(c[o], PROTO_AUTO,
		CONF_FLAG_CC_OVERRIDE, "protocol");
	case OPT_DIRECTORY:
	  return sc_str(c[o], 0,
		CONF_FLAG_CC_OVERRIDE, "directory");
	case OPT_TIMESTAMP_FORMAT:
	  return sc_str(c[o], 0,
		CONF_FLAG_CC_OVERRIDE, "timestamp_format");
	case OPT_CLIENTCONFDIR:
	  return sc_str(c[o], 0,
		CONF_FLAG_CC_OVERRIDE, "clientconfdir");
	case OPT_FORK:
	  return sc_int(c[o], 1, 0, "fork");
	case OPT_DIRECTORY_TREE:
	  return sc_int(c[o], 1,
		CONF_FLAG_CC_OVERRIDE, "directory_tree");
	case OPT_PASSWORD_CHECK:
	  return sc_int(c[o], 1,
		CONF_FLAG_CC_OVERRIDE, "password_check");
	case OPT_MANUAL_DELETE:
	  return sc_str(c[o], 0,
		CONF_FLAG_CC_OVERRIDE, "manual_delete");
	case OPT_MONITOR_BROWSE_CACHE:
	  return sc_int(c[o], 0,
		CONF_FLAG_CC_OVERRIDE, "monitor_browse_cache");
	case OPT_S_SCRIPT_PRE:
	  return sc_str(c[o], 0,
		CONF_FLAG_CC_OVERRIDE, "server_script_pre");
	case OPT_S_SCRIPT_PRE_ARG:
	  return sc_lst(c[o], 0,
		CONF_FLAG_CC_OVERRIDE|CONF_FLAG_STRLIST_REPLACE, "server_script_pre_arg");
	case OPT_S_SCRIPT_PRE_NOTIFY:
	  return sc_int(c[o], 0,
		CONF_FLAG_CC_OVERRIDE, "server_script_pre_notify");
	case OPT_S_SCRIPT_POST:
	  return sc_str(c[o], 0,
		CONF_FLAG_CC_OVERRIDE, "server_script_post");
	case OPT_S_SCRIPT_POST_ARG:
	  return sc_lst(c[o], 0,
		CONF_FLAG_CC_OVERRIDE|CONF_FLAG_STRLIST_REPLACE, "server_script_post_arg");
	case OPT_S_SCRIPT_POST_RUN_ON_FAIL:
	  return sc_int(c[o], 0,
		CONF_FLAG_CC_OVERRIDE, "server_script_post_run_on_fail");
	case OPT_S_SCRIPT_POST_NOTIFY:
	  return sc_int(c[o], 0,
		CONF_FLAG_CC_OVERRIDE, "server_script_post_notify");
	case OPT_S_SCRIPT:
	  return sc_str(c[o], 0,
		CONF_FLAG_CC_OVERRIDE, "server_script");
	case OPT_S_SCRIPT_ARG:
	  return sc_lst(c[o], 0,
		CONF_FLAG_CC_OVERRIDE|CONF_FLAG_STRLIST_REPLACE, "server_script_arg");
	case OPT_S_SCRIPT_NOTIFY:
	  return sc_int(c[o], 0,
		CONF_FLAG_CC_OVERRIDE, "server_script_notify");
	case OPT_HARDLINKED_ARCHIVE:
	  return sc_int(c[o], 0,
		CONF_FLAG_CC_OVERRIDE, "hardlinked_archive");
	case OPT_KEEP:
	  return sc_lst(c[o], 0,
		CONF_FLAG_CC_OVERRIDE|CONF_FLAG_STRLIST_REPLACE, "keep");
	case OPT_LIBRSYNC:
	  return sc_int(c[o], 1,
		CONF_FLAG_CC_OVERRIDE, "librsync");
	case OPT_LIBRSYNC_MAX_SIZE:
	  return sc_u64(c[o], 0,
		CONF_FLAG_CC_OVERRIDE, "librsync_max_size");
	case OPT_COMPRESSION:
	  return sc_int(c[o], 9,
		CONF_FLAG_CC_OVERRIDE, "compression");
	case OPT_VERSION_WARN:
	  return sc_int(c[o], 1,
		CONF_FLAG_CC_OVERRIDE, "version_warn");
	case OPT_PATH_LENGTH_WARN:
	  return sc_int(c[o], 1,
		CONF_FLAG_CC_OVERRIDE, "path_length_warn");
	case OPT_HARD_QUOTA:
	  return sc_u64(c[o], 0,
		CONF_FLAG_CC_OVERRIDE, "hard_quota");
	case OPT_SOFT_QUOTA:
	  return sc_u64(c[o], 0,
		CONF_FLAG_CC_OVERRIDE, "soft_quota");
	case OPT_TIMER_SCRIPT:
	  return sc_str(c[o], 0,
		CONF_FLAG_CC_OVERRIDE, "timer_script");
	case OPT_TIMER_ARG:
	  return sc_lst(c[o], 0,
		CONF_FLAG_CC_OVERRIDE|CONF_FLAG_STRLIST_REPLACE, "timer_arg");
	case OPT_TIMER_REPEAT_INTERVAL:
	  return sc_int(c[o], 0,
		CONF_FLAG_CC_OVERRIDE, "timer_repeat_interval");
	case OPT_LABEL:
	  return sc_lst(c[o], 0,
		CONF_FLAG_CC_OVERRIDE|CONF_FLAG_STRLIST_REPLACE, "label");
	case OPT_N_SUCCESS_SCRIPT:
	  return sc_str(c[o], 0,
		CONF_FLAG_CC_OVERRIDE, "notify_success_script");
	case OPT_N_SUCCESS_ARG:
	  return sc_lst(c[o], 0,
		CONF_FLAG_CC_OVERRIDE|CONF_FLAG_STRLIST_REPLACE, "notify_success_arg");
	case OPT_N_SUCCESS_WARNINGS_ONLY:
	  return sc_int(c[o], 0,
		CONF_FLAG_CC_OVERRIDE, "notify_success_warnings_only");
	case OPT_N_SUCCESS_CHANGES_ONLY:
	  return sc_int(c[o], 0,
		CONF_FLAG_CC_OVERRIDE, "notify_success_changes_only");
	case OPT_N_FAILURE_SCRIPT:
	  return sc_str(c[o], 0,
		CONF_FLAG_CC_OVERRIDE, "notify_failure_script");
	case OPT_N_FAILURE_ARG:
	  return sc_lst(c[o], 0,
		CONF_FLAG_CC_OVERRIDE|CONF_FLAG_STRLIST_REPLACE, "notify_failure_arg");
	case OPT_N_FAILURE_BACKUP_FAILOVERS_LEFT:
	  return sc_int(c[o], 1,
		CONF_FLAG_CC_OVERRIDE, "notify_failure_on_backup_with_failovers_left");
	case OPT_N_FAILURE_BACKUP_WORKING_DELETION:
	  return sc_int(c[o], 0,
		CONF_FLAG_CC_OVERRIDE, "notify_failure_on_backup_working_dir_deletion");
	case OPT_RESTORE_CLIENTS:
	  return sc_lst(c[o], 0,
		CONF_FLAG_CC_OVERRIDE|CONF_FLAG_STRLIST_SORTED, "restore_client");
	case OPT_SUPER_CLIENTS:
	  return sc_lst(c[o], 0,
		CONF_FLAG_CC_OVERRIDE|CONF_FLAG_STRLIST_SORTED, "super_client");
	case OPT_DEDUP_GROUP:
	  return sc_str(c[o], 0,
		CONF_FLAG_CC_OVERRIDE, "dedup_group");
	case OPT_CLIENT_CAN_DELETE:
	  return sc_int(c[o], 1,
		CONF_FLAG_CC_OVERRIDE, "client_can_delete");
	case OPT_CLIENT_CAN_DIFF:
	  return sc_int(c[o], 1,
		CONF_FLAG_CC_OVERRIDE, "client_can_diff");
	case OPT_CLIENT_CAN_FORCE_BACKUP:
	  return sc_int(c[o], 1,
		CONF_FLAG_CC_OVERRIDE, "client_can_force_backup");
	case OPT_CLIENT_CAN_LIST:
	  return sc_int(c[o], 1,
		CONF_FLAG_CC_OVERRIDE, "client_can_list");
	case OPT_CLIENT_CAN_MONITOR:
	  return sc_int(c[o], 1,
		CONF_FLAG_CC_OVERRIDE, "client_can_monitor");
	case OPT_CLIENT_CAN_RESTORE:
	  return sc_int(c[o], 1,
		CONF_FLAG_CC_OVERRIDE, "client_can_restore");
	case OPT_CLIENT_CAN_VERIFY:
	  return sc_int(c[o], 1,
		CONF_FLAG_CC_OVERRIDE, "client_can_verify");
	case OPT_SERVER_CAN_RESTORE:
	  return sc_int(c[o], 1,
		CONF_FLAG_CC_OVERRIDE, "server_can_restore");
	case OPT_WORKING_DIR_RECOVERY_METHOD:
	  return sc_rec(c[o], RECOVERY_METHOD_DELETE,
		CONF_FLAG_CC_OVERRIDE, "working_dir_recovery_method");
	case OPT_MAX_RESUME_ATTEMPTS:
	  return sc_int(c[o], 0,
		CONF_FLAG_CC_OVERRIDE, "max_resume_attempts");
	case OPT_FAIL_ON_WARNING:
	  return sc_int(c[o], 0,
		CONF_FLAG_CC_OVERRIDE, "fail_on_warning");
	case OPT_RSHASH:
	  return sc_rsh(c[o], RSHASH_UNSET,
		CONF_FLAG_CC_OVERRIDE, "");
	case OPT_MESSAGE:
	  return sc_int(c[o], 0,
		CONF_FLAG_CC_OVERRIDE, "");
	case OPT_INCEXCDIR:
	  // This is a combination of OPT_INCLUDE and OPT_EXCLUDE, so
	  // no field name set for now.
	  return sc_lst(c[o], 0, CONF_FLAG_STRLIST_SORTED, "incexcdir");
	case OPT_STARTDIR:
	  // This is a combination of OPT_INCLUDE and OPT_EXCLUDE, so
	  // no field name set for now.
	  // Deliberately not using CONF_FLAG_STRLIST_SORTED because of the
	  // way finalise_start_dirs() works.
	  return sc_lst(c[o], 0, 0, "startdir");
	case OPT_INCLUDE:
	  // Combines with OPT_EXCLUDE to make OPT_INCEXCDIR and OPT_STARTDIR.
	  return sc_lst(c[o], 0,
		CONF_FLAG_INCEXC|CONF_FLAG_INCEXC_RESTORE|CONF_FLAG_STRLIST_SORTED, "include");
	case OPT_EXCLUDE:
	  // Combines with OPT_INCLUDE to make OPT_INCEXCDIR and OPT_STARTDIR.
	  return sc_lst(c[o], 0,
		CONF_FLAG_INCEXC|CONF_FLAG_INCEXC_RESTORE|CONF_FLAG_STRLIST_SORTED, "exclude");
	case OPT_FSCHGDIR:
	  return sc_lst(c[o], 0,
		CONF_FLAG_INCEXC|CONF_FLAG_STRLIST_SORTED, "cross_filesystem");
	case OPT_NOBACKUP:
	  return sc_lst(c[o], 0,
		CONF_FLAG_INCEXC|CONF_FLAG_STRLIST_SORTED, "nobackup");
	case OPT_INCEXT:
	  return sc_lst(c[o], 0,
		CONF_FLAG_INCEXC|CONF_FLAG_STRLIST_SORTED, "include_ext");
	case OPT_EXCEXT:
	  return sc_lst(c[o], 0,
		CONF_FLAG_INCEXC|CONF_FLAG_STRLIST_SORTED, "exclude_ext");
	case OPT_INCREG:
	  return sc_lst(c[o], 0,
		CONF_FLAG_INCEXC|CONF_FLAG_STRLIST_SORTED, "include_regex");
	case OPT_EXCREG:
	  return sc_lst(c[o], 0,
		CONF_FLAG_INCEXC|CONF_FLAG_STRLIST_SORTED, "exclude_regex");
	case OPT_INCLOGIC:
	  return sc_lst(c[o], 0,
		CONF_FLAG_INCEXC|CONF_FLAG_STRLIST_SORTED, "include_logic");
	 case OPT_EXCLOGIC:
	  return sc_lst(c[o], 0,
		CONF_FLAG_INCEXC|CONF_FLAG_STRLIST_SORTED, "exclude_logic");
	case OPT_EXCFS:
	  return sc_lst(c[o], 0,
		CONF_FLAG_INCEXC|CONF_FLAG_STRLIST_SORTED, "exclude_fs");
	case OPT_INCFS:
	  return sc_lst(c[o], 0,
		CONF_FLAG_INCEXC|CONF_FLAG_STRLIST_SORTED, "include_fs");
	case OPT_EXCOM:
	  return sc_lst(c[o], 0,
		CONF_FLAG_INCEXC|CONF_FLAG_STRLIST_SORTED, "exclude_comp");
	case OPT_INCGLOB:
	  return sc_lst(c[o], 0,
		CONF_FLAG_INCEXC|CONF_FLAG_STRLIST_SORTED, "include_glob");
	case OPT_SEED_SRC:
	  return sc_str(c[o], 0, 0, "seed_src");
	case OPT_SEED_DST:
	  return sc_str(c[o], 0, 0, "seed_dst");
	case OPT_CROSS_ALL_FILESYSTEMS:
	  return sc_int(c[o], 0, CONF_FLAG_INCEXC, "cross_all_filesystems");
	case OPT_READ_ALL_FIFOS:
	  return sc_int(c[o], 0, CONF_FLAG_INCEXC, "read_all_fifos");
	case OPT_FIFOS:
	  return sc_lst(c[o], 0, CONF_FLAG_INCEXC, "read_fifo");
	case OPT_READ_ALL_BLOCKDEVS:
	  return sc_int(c[o], 0, CONF_FLAG_INCEXC, "read_all_blockdevs");
	case OPT_BLOCKDEVS:
	  return sc_lst(c[o], 0, CONF_FLAG_INCEXC, "read_blockdev");
	case OPT_MIN_FILE_SIZE:
	  return sc_u64(c[o], 0, CONF_FLAG_INCEXC, "min_file_size");
	case OPT_MAX_FILE_SIZE:
	  return sc_u64(c[o], 0, CONF_FLAG_INCEXC, "max_file_size");
	case OPT_SPLIT_VSS:
	  return sc_int(c[o], 0, CONF_FLAG_INCEXC, "split_vss");
	case OPT_STRIP_VSS:
	  return sc_int(c[o], 0, CONF_FLAG_INCEXC, "strip_vss");
	case OPT_VSS_DRIVES:
	  return sc_str(c[o], 0, CONF_FLAG_INCEXC, "vss_drives");
	case OPT_ACL:
	  return sc_int(c[o], 1, CONF_FLAG_INCEXC, "acl");
	case OPT_XATTR:
	  return sc_int(c[o], 1, CONF_FLAG_INCEXC, "xattr");
	case OPT_ATIME:
	  return sc_int(c[o], 0, CONF_FLAG_INCEXC, "atime");
	case OPT_SCAN_PROBLEM_RAISES_ERROR:
	  return sc_int(c[o], 0, CONF_FLAG_INCEXC, "scan_problem_raises_error");
	case OPT_OVERWRITE:
	  return sc_int(c[o], 0,
		CONF_FLAG_INCEXC|CONF_FLAG_INCEXC_RESTORE, "overwrite");
	case OPT_STRIP:
	  return sc_int(c[o], 0,
		CONF_FLAG_INCEXC|CONF_FLAG_INCEXC_RESTORE, "strip");
	case OPT_REGEX:
	  return sc_str(c[o], 0,
		CONF_FLAG_INCEXC|CONF_FLAG_INCEXC_RESTORE, "regex");
	case OPT_REGEX_CASE_INSENSITIVE:
	  return sc_int(c[o], 0,
		CONF_FLAG_INCEXC|CONF_FLAG_INCEXC_RESTORE, "regex_case_insensitive");
	case OPT_MAX:
	  return 0;
	// No default, so we get compiler warnings if something was missed.
	}
	return -1;
}

static int set_conf(struct conf *c, const char *value)
{
	switch(c->conf_type)
	{
		case CT_STRING:
			if(set_string(c, value)) return 1;
			break;
		case CT_FLOAT:
			if(set_float(c, atof(value))) return 1;
			break;
		case CT_E_BURP_MODE:
		{
			enum burp_mode bm;
			bm=str_to_burp_mode(value);
			if(bm==BURP_MODE_UNSET
			  || set_e_burp_mode(c, bm))
				return 1;
			break;
		}
		case CT_E_RECOVERY_METHOD:
		{
			enum recovery_method rm;
			rm=str_to_recovery_method(value);
			if(rm==RECOVERY_METHOD_UNSET
			  || set_e_recovery_method(c, rm))
				return 1;
			break;
		}
	// FIX THIS
		case CT_E_RSHASH:
		case CT_UINT:
		case CT_MODE_T:
		case CT_SSIZE_T:
		case CT_E_PROTOCOL:
		case CT_STRLIST:
		case CT_CNTR:
			break;
	}
	return 0;
}

int conf_set(struct conf **confs, const char *field, const char *value)
{
	int i=0;
	int r=0;
	for(i=0; i<OPT_MAX; i++)
	{
		if(strcmp(confs[i]->field, field)) continue;
		r+=set_conf(confs[i], value);
	}
	return r;
}

static char *conf_data_to_str(struct conf *conf)
{
	size_t l=256;
	char *ret=NULL;
	if(!conf->field || !*conf->field)
		return NULL;
	if(!(ret=(char *)calloc_w(1, l, __func__))) return ret;
	*ret='\0';
	switch(conf->conf_type)
	{
		case CT_STRING:
			snprintf(ret, l, "%32s: %s\n", conf->field,
				get_string(conf)?get_string(conf):"");
			break;
		case CT_FLOAT:
			snprintf(ret, l, "%32s: %g\n", conf->field,
				get_float(conf));
			break;
		case CT_E_BURP_MODE:
			snprintf(ret, l, "%32s: %s\n", conf->field,
				burp_mode_to_str(get_e_burp_mode(conf)));
			break;
		case CT_E_PROTOCOL:
			snprintf(ret, l, "%32s: %d\n", conf->field,
				get_e_protocol(conf));
			break;
		case CT_E_RECOVERY_METHOD:
			snprintf(ret, l, "%32s: %s\n", conf->field,
				recovery_method_to_str(
					get_e_recovery_method(conf)));
			break;
		case CT_E_RSHASH:
			snprintf(ret, l, "%32s: %s\n", conf->field,
				rshash_to_str(get_e_rshash(conf)));
			break;
		case CT_UINT:
			snprintf(ret, l, "%32s: %u\n", conf->field,
				get_int(conf));
			break;
		case CT_STRLIST:
		{
			int count=0;
			char piece[256]="";
			struct strlist *s;
			for(s=get_strlist(conf); s; s=s->next)
			{
				snprintf(piece, sizeof(piece),
					"%32s: %s\n", conf->field, s->path);
				if(astrcat(&ret, piece, __func__))
					return ret;
				count++;
			}
			if(!count)
			snprintf(ret, l, "%32s:\n", conf->field);
			break;
		}
		case CT_MODE_T:
			snprintf(ret, l, "%32s: %o\n", conf->field,
				get_mode_t(conf));
			break;
		case CT_SSIZE_T:
			snprintf(ret, l, "%32s: %" PRIu64 "\n", conf->field,
				get_uint64_t(conf));
			break;
		case CT_CNTR:
			break;
	}
	return ret;

}

struct conf **confs_alloc(void)
{
	int i=0;
	struct conf **confs=NULL;
	if(!(confs=(struct conf **)
		calloc_w(OPT_MAX, sizeof(struct conf *), __func__)))
			return NULL;
	for(i=0; i<OPT_MAX; i++)
	{
		struct conf *c;
		if(!(c=(struct conf *)
			calloc_w(1, sizeof(struct conf), __func__)))
				return NULL;
		confs[i]=c;
	}
	return confs;
};

void confs_free(struct conf ***confs)
{
	int i=0;
	if(!confs || !*confs) return;
	confs_free_content(*confs);
	for(i=0; i<OPT_MAX; i++)
		free_v((void **)&((*confs)[i]));
	free_v((void **)confs);
	*confs=NULL;
}

int confs_init(struct conf **confs)
{
	int i=0;
	for(i=0; i<OPT_MAX; i++)
		if(reset_conf(confs, (enum conf_opt)i))
			return -1;
	return 0;
}

int confs_dump(struct conf **confs, int flags)
{
	int i=0;
	char *str=NULL;
	for(i=0; i<OPT_MAX; i++)
	{
		if(flags && !(flags & confs[i]->flags)) continue;
	//	if(!*(confs[i]->field)) continue;
		str=conf_data_to_str(confs[i]);
		if(str && *str) printf("%s", str);
		free_w(&str);
	}
	return 0;
}
