#include "burp.h"
#include "prog.h"
#include "counter.h"
#include "conf.h"
#include "msg.h"
#include "strlist.h"
#include "prepend.h"

/* Init only stuff related to includes/excludes.
   This is so that the server can override them all on the client. */
static void init_incexcs(struct config *conf)
{
	conf->startdir=NULL; conf->sdcount=0;
	conf->incexcdir=NULL; conf->iecount=0;
	conf->fschgdir=NULL; conf->fscount=0;
	conf->nobackup=NULL; conf->nbcount=0;
	conf->incext=NULL; conf->incount=0; // include extensions
	conf->excext=NULL; conf->excount=0; // exclude extensions
	conf->excfs=NULL; conf->exfscount=0; // exclude filesystems
	conf->fifos=NULL; conf->ffcount=0;
	/* stuff to do with restore */
	conf->overwrite=0;
	conf->strip=0;
	conf->backup=NULL;
	conf->restoreprefix=NULL;
	conf->regex=NULL;
}

/* Free only stuff related to includes/excludes.
   This is so that the server can override them all on the client. */
static void free_incexcs(struct config *conf)
{
	strlists_free(conf->startdir, conf->sdcount);
	strlists_free(conf->incexcdir, conf->iecount);
	strlists_free(conf->fschgdir, conf->fscount);
	strlists_free(conf->nobackup, conf->nbcount);
	strlists_free(conf->incext, conf->incount); // include extensions
	strlists_free(conf->excext, conf->excount); // exclude extensions
	strlists_free(conf->excfs, conf->exfscount); // exclude filesystems
	strlists_free(conf->fifos, conf->ffcount);
	if(conf->backup) free(conf->backup);
	if(conf->restoreprefix) free(conf->restoreprefix);
	if(conf->regex) free(conf->regex);
	init_incexcs(conf);
}

void init_config(struct config *conf)
{
	conf->configfile=NULL;
	conf->mode=MODE_UNSET;
	conf->port=NULL;
	conf->status_port=NULL;
	conf->hardlinked_archive=0;
	conf->working_dir_recovery_method=NULL;
	conf->forking=0;
	conf->daemon=0;
	conf->clientconfdir=NULL;
	conf->cname=NULL;
	conf->directory=NULL;
	conf->ca_conf=NULL;
	conf->ca_name=NULL;
	conf->ca_server_name=NULL;
	conf->ca_burp_ca=NULL;
	conf->ca_csr_dir=NULL;
	conf->lockfile=NULL;
	conf->logfile=NULL;
	conf->syslog=0;
	conf->password=NULL;
	conf->passwd=NULL;
	conf->server=NULL;
	conf->ratelimit=0;
	conf->network_timeout=60*60*2; // two hours
	conf->cross_all_filesystems=0;
	conf->read_all_fifos=0;
	conf->min_file_size=0;
	conf->max_file_size=0;
	conf->autoupgrade_dir=NULL;
	conf->autoupgrade_os=NULL;
	conf->ssl_cert_ca=NULL;
        conf->ssl_cert=NULL;
        conf->ssl_key=NULL;
        conf->ssl_key_password=NULL;
	conf->ssl_dhfile=NULL;
	conf->ssl_peer_cn=NULL;
	conf->encryption_password=NULL;
	conf->max_children=0;
	conf->max_status_children=0;
	// ext3 maximum number of subdirs is 32000, so leave a little room.
	conf->max_storage_subdirs=30000;
	conf->librsync=1;
	conf->compression=9;
	conf->client_lockdir=NULL;
	conf->umask=0022;
	conf->user=NULL;
	conf->group=NULL;
	conf->keep=NULL;
	conf->kpcount=0;
	conf->max_hardlinks=10000;

	conf->timer_script=NULL;
	conf->timer_arg=NULL;
	conf->tacount=0;

	conf->notify_success_script=NULL;
	conf->notify_success_arg=NULL;
	conf->nscount=0;
	conf->notify_success_warnings_only=0;

	conf->notify_failure_script=NULL;
	conf->notify_failure_arg=NULL;
	conf->nfcount=0;

	conf->backup_script_pre=NULL;
	conf->backup_script_pre_arg=NULL;
	conf->bprecount=0;

	conf->backup_script_post=NULL;
	conf->backup_script_post_arg=NULL;
	conf->bpostcount=0;
	conf->backup_script_post_run_on_fail=0;

	conf->restore_script_pre=NULL;
	conf->restore_script_pre_arg=NULL;
	conf->rprecount=0;

	conf->restore_script_post=NULL;
	conf->restore_script_post_arg=NULL;
	conf->rpostcount=0;
	conf->restore_script_post_run_on_fail=0;

	conf->server_script_pre=NULL;
	conf->server_script_pre_arg=NULL;
	conf->sprecount=0;

	conf->server_script_post=NULL;
	conf->server_script_post_arg=NULL;
	conf->spostcount=0;
	conf->server_script_post_run_on_fail=0;

	conf->backup_script=NULL;
	conf->backup_script_arg=NULL;
	conf->bscount=0;
	conf->restore_script=NULL;
	conf->restore_script_arg=NULL;
	conf->rscount=0;

	conf->server_script=NULL;
	conf->server_script_arg=NULL;
	conf->sscount=0;

	conf->dedup_group=NULL;
	conf->browsefile=NULL;
	conf->browsedir=NULL;
	init_incexcs(conf);
}

void free_config(struct config *conf)
{
	if(!conf) return;
	if(conf->configfile) free(conf->configfile);
	if(conf->clientconfdir) free(conf->clientconfdir);
	if(conf->cname) free(conf->cname);
	if(conf->directory) free(conf->directory);
	if(conf->ca_conf) free(conf->ca_conf);
	if(conf->ca_name) free(conf->ca_name);
	if(conf->ca_server_name) free(conf->ca_server_name);
	if(conf->ca_burp_ca) free(conf->ca_burp_ca);
	if(conf->ca_csr_dir) free(conf->ca_csr_dir);
	if(conf->lockfile) free(conf->lockfile);
	if(conf->logfile) free(conf->logfile);
	if(conf->password) free(conf->password);
	if(conf->passwd) free(conf->passwd);
	if(conf->server) free(conf->server);
	if(conf->working_dir_recovery_method)
		free(conf->working_dir_recovery_method);
 	if(conf->ssl_cert_ca) free(conf->ssl_cert_ca);
        if(conf->ssl_cert) free(conf->ssl_cert);
        if(conf->ssl_key) free(conf->ssl_key);
        if(conf->ssl_key_password) free(conf->ssl_key_password);
        if(conf->ssl_dhfile) free(conf->ssl_dhfile);
        if(conf->ssl_peer_cn) free(conf->ssl_peer_cn);
        if(conf->user) free(conf->user);
        if(conf->group) free(conf->group);
        if(conf->encryption_password) free(conf->encryption_password);
	if(conf->client_lockdir) free(conf->client_lockdir);
	if(conf->autoupgrade_dir) free(conf->autoupgrade_dir);
	if(conf->autoupgrade_os) free(conf->autoupgrade_os);

	if(conf->timer_script) free(conf->timer_script);
	strlists_free(conf->timer_arg, conf->tacount);

	if(conf->notify_success_script) free(conf->notify_success_script);
	strlists_free(conf->notify_success_arg, conf->nscount);

	if(conf->notify_failure_script) free(conf->notify_failure_script);
	strlists_free(conf->notify_failure_arg, conf->nfcount);

	if(conf->backup_script_pre) free(conf->backup_script_pre);
	strlists_free(conf->backup_script_pre_arg, conf->bprecount);
	if(conf->backup_script_post) free(conf->backup_script_post);
	strlists_free(conf->backup_script_post_arg, conf->bpostcount);
	if(conf->restore_script_pre) free(conf->restore_script_pre);
	strlists_free(conf->restore_script_pre_arg, conf->rprecount);
	if(conf->restore_script_post) free(conf->restore_script_post);
	strlists_free(conf->restore_script_post_arg, conf->rpostcount);

	if(conf->server_script_pre) free(conf->server_script_pre);
	strlists_free(conf->server_script_pre_arg, conf->sprecount);
	if(conf->server_script_post) free(conf->server_script_post);
	strlists_free(conf->server_script_post_arg, conf->spostcount);

	if(conf->backup_script) free(conf->backup_script);
	if(conf->restore_script) free(conf->restore_script);
	strlists_free(conf->backup_script_arg, conf->bscount);
	strlists_free(conf->restore_script_arg, conf->rscount);

	if(conf->server_script) free(conf->server_script);
	strlists_free(conf->server_script_arg, conf->sscount);

	strlists_free(conf->keep, conf->kpcount);

	if(conf->dedup_group) free(conf->dedup_group);
	if(conf->browsefile) free(conf->browsefile);
	if(conf->browsedir) free(conf->browsedir);

	free_incexcs(conf);

	init_config(conf);
}

static int get_conf_val(const char *field, const char *value, const char *want, char **dest)
{
	if(!strcmp(field, want))
	{
		if(*dest) free(*dest);
		if(!(*dest=strdup(value)))
		{
			logp("could not strdup %s value: %s\n", field, value);
			return -1;
		}
	}
	return 0;
}

static void get_conf_val_int(const char *field, const char *value, const char *want, int *dest)
{
	if(!strcmp(field, want)) *dest=atoi(value);
}

int config_get_pair(char buf[], char **field, char **value)
{
	char *cp=NULL;
	char *eq=NULL;
	char *end=NULL;

	// strip leading space
	for(cp=buf; *cp && isspace(*cp); cp++) { }
	if(!*cp || *cp=='#')
	{
		*field=NULL;
		*value=NULL;
		return 0;
	}
	*field=cp;
	if(!(eq=strchr(*field, '='))) return -1;
	*eq='\0';

	// strip white space from before the equals sign
	for(cp=eq-1; *cp && isspace(*cp); cp--) *cp='\0';
	// skip white space after the equals sign
	for(cp=eq+1; *cp && isspace(*cp); cp++) { }
	*value=cp;
	// strip white space at the end of the line
	for(cp+=strlen(cp)-1; *cp && isspace(*cp); cp--) { *cp='\0'; }
	// remove quotes from around the value.
	// TODO: Make this more sophisticated - it should understand escapes,
	// for example.
	cp=*value;
	end=cp+strlen(cp)-1;
	if((*cp=='\'' && *end=='\'')
	  || (*cp=='\"' && *end=='\"'))
	{
		*value=cp+1; 
		*end='\0';
	}

	if(!*field || !**field || !*value || !**value) return -1;

	return 0;
}

static int get_conf_val_args(const char *field, const char *value, const char *opt, struct strlist ***args, int *got_args, int *count, struct strlist ***list, int include)
{
	char *tmp=NULL;
	if(get_conf_val(field, value, opt, &tmp)) return -1;
	if(tmp)
	{
		if(got_args && *got_args && args)
		{
			strlists_free(*args, *count);
			*got_args=0;
			*args=NULL;
			*count=0;
		}
		if(strlist_add(list, count, tmp, include)) return -1;
		free(tmp); tmp=NULL;
	}
	return 0;
}

#define ABSOLUTE_ERROR	"ERROR: Please use absolute include/exclude paths.\n"
static int path_checks(const char *path)
{
	const char *p=NULL;
	if(strchr(path, '\\'))
	{
		logp("ERROR: Please use forward slashes '/' instead of backslashes '\\' in your include/exclude paths.\n");
		return -1;
	}
	for(p=path; *p; p++)
	{
		if(*p!='.' || *(p+1)!='.') continue;
		if((p==path || *(p-1)=='/') && (*(p+2)=='/' || !*(p+2)))
		{
			logp(ABSOLUTE_ERROR);
			return -1;
		}
	}
#ifdef HAVE_WIN32
	if(!isalpha(*path) || *(path+1)!=':')
	{
		logp(ABSOLUTE_ERROR);
		return -1;
	}
#else
	if(*path!='/')
	{
		logp(ABSOLUTE_ERROR);
		return -1;
	}
#endif
	return 0;
}

/* is_subdir() and pathcmp() included in conf.c so that bedup can include
   conf.c and not much more else. */

// Return a number indicating the number of directories matched (plus one).
// 0 if it is not a sub-directory.
// Two paths the same counts as a subdirectory.
int is_subdir(const char *dir, const char *sub)
{
	int count=1;
	const char *d=NULL;
	const char *s=NULL;
	const char *dl=NULL;
	const char *sl=NULL;
	if(!sub || !dir) return 0;
	for(s=sl=sub, dl=d=dir; *s && *d; s++, d++)
	{
		if(*s!=*d) break;
		sl=s;
		dl=d;
		if(*s=='/') count++;
	}
	if(!*d && !*s) return ++count; // Paths were exactly the same.
	if(!*d && *s=='/')
		return ++count; // 'dir' ended without a slash, for example:
	// dir=/bin sub=/bin/bash
	if(*dl=='/' && *sl=='/' && *(sl+1) && !*(dl+1)) return count;
	return 0;
}

int pathcmp(const char *a, const char *b)
{
	const char *x=NULL;
	const char *y=NULL;
	if(!a && !b) return 0; // equal
	if( a && !b) return 1; // a is longer
	if(!a &&  b) return -1; // b is longer
	for(x=a, y=b; *x && *y ; x++, y++)
	{
		if(*x==*y) continue;
		if(*x=='/' && *y!='/') return -1;
		if(*x!='/' && *y=='/') return 1;
		if(*x<*y) return -1;
		if(*x>*y) return 1;
	}
	if(!*x && !*y) return 0; // equal
	if( *x && !*y) return 1; // x is longer
	return -1; // y is longer
}

static int conf_error(const char *config_path, int line)
{
	logp("%s: parse error on line %d\n", config_path, line);
	return -1;
}

static int get_file_size(const char *value, unsigned long *dest, const char *config_path, int line)
{
	// Store in bytes, allow k/m/g.
	const char *cp=NULL;
	*dest=strtoul(value, NULL, 10);
	for(cp=value; *cp && (isspace(*cp) || isdigit(*cp)); cp++) { }
	if(tolower(*cp)=='k') *dest*=1024;
	else if(tolower(*cp)=='m') *dest*=1024*1024;
	else if(tolower(*cp)=='g') *dest*=1024*1024*1024;
	else if(!*cp || *cp=='b')
	{ }
	else
	{
		logp("Unknown file size type '%s' - please use b/kb/mb/gb\n",
			cp);
		return conf_error(config_path, line);
	}
	return 0;
}

static int pre_post_override(char **override, char **pre, char **post)
{
	if(!override || !*override) return 0;
	if(*pre) free(*pre);
	if(*post) free(*post);
	if(!(*pre=strdup(*override))
	  || !(*post=strdup(*override)))
	{
		logp("out of memory\n");
		return -1;
	}
	free(*override);
	*override=NULL;
	return 0;
}

static int setup_script_arg_override(struct strlist **list, int count, struct strlist ***prelist, struct strlist ***postlist, int *precount, int *postcount)
{
	int i=0;
	if(!list) return 0;
	strlists_free(*prelist, *precount);
	strlists_free(*postlist, *postcount);
	*precount=0;
	*postcount=0;
	for(i=0; i<count; i++)
	{
		if(strlist_add(prelist, precount,
			list[i]->path, 0)) return -1;
		if(strlist_add(postlist, postcount,
			list[i]->path, 0)) return -1;
	}
	return 0;
}

static void do_strlist_sort(struct strlist **list, int count, struct strlist ***dest)
{
	if(count) qsort(list, count, sizeof(*list),
		(int (*)(const void *, const void *))strlist_sort);
	*dest=list;
}

#ifdef HAVE_LINUX_OS
struct fstype
{
	const char *str;
	long flag;
};

static struct fstype fstypes[]={
	{ "debugfs",		0x64626720 },
	{ "devfs",		0x00001373 },
	{ "devpts",		0x00001CD1 },
	{ "ext2",		0x0000EF53 },
	{ "ext3",		0x0000EF53 },
	{ "ext4",		0x0000EF53 },
	{ "iso9660",		0x00009660 },
	{ "jfs",		0x3153464A },
	{ "nfs",		0x00006969 },
	{ "ntfs",		0x5346544E },
	{ "proc",		0x00009fa0 },
	{ "reiserfs",		0x52654973 },
	{ "securityfs",		0x73636673 },
	{ "sysfs",		0x62656572 },
	{ "smbfs",		0x0000517B },
	{ "usbdevfs",		0x00009fa2 },
	{ "xfs",		0x58465342 },
	{ "ramfs",		0x858458f6 },
	{ "romfs",		0x00007275 },
	{ "tmpfs",		0x01021994 },
	{ NULL,			0 },
};
#endif

static int fstype_to_flag(const char *fstype, long *flag)
{
#ifdef HAVE_LINUX_OS
	int i=0;
	for(i=0; fstypes[i].str; i++)
	{
		if(!strcmp(fstypes[i].str, fstype))
		{
			*flag=fstypes[i].flag;
			return 0;
		}
	}
#else
	return 0;
#endif
	return -1;
}

struct llists
{
	struct strlist **kplist;
	struct strlist **ielist;
	struct strlist **fslist;
	struct strlist **nblist;
	struct strlist **fflist;
	struct strlist **inlist; // include extensions
	struct strlist **exlist; // exclude extensions
	struct strlist **exfslist; // exclude filesystems
	struct strlist **talist;
	struct strlist **nslist;
	struct strlist **nflist;
	struct strlist **bprelist;
	struct strlist **bpostlist;
	struct strlist **rprelist;
	struct strlist **rpostlist;
	struct strlist **sprelist;
	struct strlist **spostlist;
	struct strlist **bslist;
	struct strlist **rslist;
	struct strlist **sslist;
	int got_kp_args;
	int got_timer_args;
	int got_ns_args;
	int got_nf_args;
	int got_spre_args;
	int got_spost_args;
	int got_ss_args;
};

static int load_config_ints(struct config *conf, const char *field, const char *value)
{
	get_conf_val_int(field, value, "syslog",
		&(conf->syslog));
	get_conf_val_int(field, value, "hardlinked_archive",
		&(conf->hardlinked_archive));
	get_conf_val_int(field, value, "max_hardlinks",
		&(conf->max_hardlinks));
	get_conf_val_int(field, value, "librsync",
		&(conf->librsync));
	get_conf_val_int(field, value, "cross_all_filesystems",
		&(conf->cross_all_filesystems));
	get_conf_val_int(field, value, "read_all_fifos",
		&(conf->read_all_fifos));
	get_conf_val_int(field, value, "backup_script_post_run_on_fail",
		&(conf->backup_script_post_run_on_fail));
	get_conf_val_int(field, value, "server_script_post_run_on_fail",
		&(conf->server_script_post_run_on_fail));
	get_conf_val_int(field, value, "notify_success_warnings_only",
		&(conf->notify_success_warnings_only));
	get_conf_val_int(field, value, "network_timeout",
		&(conf->network_timeout));
	get_conf_val_int(field, value, "max_children",
		&(conf->max_children));
	get_conf_val_int(field, value, "max_status_children",
		&(conf->max_status_children));
	get_conf_val_int(field, value, "max_storage_subdirs",
		&(conf->max_storage_subdirs));
	get_conf_val_int(field, value, "overwrite",
		&(conf->overwrite));
	get_conf_val_int(field, value, "strip",
		&(conf->strip));
	get_conf_val_int(field, value, "fork",
		&(conf->forking));
	get_conf_val_int(field, value, "daemon",
		&(conf->daemon));

	return 0;
}

static int load_config_strings(struct config *conf, const char *field, const char *value, struct llists *l)
{
	if(get_conf_val(field, value, "port", &(conf->port)))
		return -1;
	if(get_conf_val(field, value, "status_port", &(conf->status_port)))
		return -1;
	if(get_conf_val(field, value, "ssl_cert_ca", &(conf->ssl_cert_ca)))
		return -1;
	if(get_conf_val(field, value, "ssl_cert", &(conf->ssl_cert)))
		return -1;
	if(get_conf_val(field, value, "ssl_key", &(conf->ssl_key)))
		return -1;
	// ssl_cert_password is a synonym for ssl_key_password
	if(get_conf_val(field, value, "ssl_cert_password",
		&(conf->ssl_key_password))) return -1;
	if(get_conf_val(field, value, "ssl_key_password",
		&(conf->ssl_key_password))) return -1;
	if(get_conf_val(field, value, "ssl_dhfile", &(conf->ssl_dhfile)))
		return -1;
	if(get_conf_val(field, value, "ssl_peer_cn", &(conf->ssl_peer_cn)))
		return -1;
	if(get_conf_val(field, value, "clientconfdir", &(conf->clientconfdir)))
		return -1;
	if(get_conf_val(field, value, "cname", &(conf->cname)))
		return -1;
	if(get_conf_val(field, value, "directory", &(conf->directory)))
		return -1;
	if(get_conf_val(field, value, "ca_conf", &(conf->ca_conf)))
		return -1;
	if(get_conf_val(field, value, "ca_name", &(conf->ca_name)))
		return -1;
	if(get_conf_val(field, value, "ca_server_name",
		&(conf->ca_server_name))) return -1;
	if(get_conf_val(field, value, "ca_burp_ca",
		&(conf->ca_burp_ca))) return -1;
	if(get_conf_val(field, value, "ca_csr_dir",
		&(conf->ca_csr_dir))) return -1;
	if(get_conf_val(field, value, "backup", &(conf->backup)))
		return -1;
	if(get_conf_val(field, value, "restoreprefix", &(conf->restoreprefix)))
		return -1;
	if(get_conf_val(field, value, "regex", &(conf->regex)))
		return -1;
	if(get_conf_val(field, value, "browsedir", &(conf->browsedir)))
		return -1;
	if(get_conf_val(field, value, "browsefile", &(conf->browsefile)))
		return -1;
	if(get_conf_val(field, value, "working_dir_recovery_method",
		&(conf->working_dir_recovery_method))) return -1;
	if(get_conf_val(field, value, "autoupgrade_dir",
		&(conf->autoupgrade_dir))) return -1;
	if(get_conf_val(field, value, "autoupgrade_os",
		&(conf->autoupgrade_os))) return -1;
	if(get_conf_val(field, value, "lockfile", &(conf->lockfile)))
		return -1;
	// "pidfile" is a synonym for "lockfile".
	if(get_conf_val(field, value, "pidfile", &(conf->lockfile)))
		return -1;
	if(get_conf_val(field, value, "logfile", &(conf->logfile))) return -1;
	if(get_conf_val(field, value, "password", &(conf->password))) return -1;
	if(get_conf_val(field, value, "passwd", &(conf->passwd))) return -1;
	if(get_conf_val(field, value, "server", &(conf->server))) return -1;
	if(get_conf_val(field, value, "user", &(conf->user))) return -1;
	if(get_conf_val(field, value, "group", &(conf->group))) return -1;
	if(get_conf_val(field, value, "client_lockdir",
		&(conf->client_lockdir))) return -1;
	if(get_conf_val(field, value, "encryption_password",
		&(conf->encryption_password))) return -1;
	if(get_conf_val_args(field, value, "keep", &(conf->keep),
		&(l->got_kp_args), &(conf->kpcount), &(l->kplist), 1))
			return -1;
	if(get_conf_val_args(field, value, "include", NULL,
		NULL, &(conf->iecount), &(l->ielist), 1)) return -1;
	if(get_conf_val_args(field, value, "exclude", NULL,
		NULL, &(conf->iecount), &(l->ielist), 0)) return -1;
	if(get_conf_val_args(field, value, "cross_filesystem", NULL,
		NULL, &(conf->fscount), &(l->fslist), 0)) return -1;
	if(get_conf_val_args(field, value, "nobackup", NULL,
		NULL, &(conf->nbcount), &(l->nblist), 0)) return -1;
	if(get_conf_val_args(field, value, "read_fifo", NULL,
		NULL, &(conf->ffcount), &(l->fflist), 0)) return -1;
	if(get_conf_val_args(field, value, "include_ext", NULL,
		NULL, &(conf->incount), &(l->inlist), 0)) return -1;
	if(get_conf_val_args(field, value, "exclude_ext", NULL,
		NULL, &(conf->excount), &(l->exlist), 0)) return -1;
	if(get_conf_val_args(field, value, "exclude_fs", NULL,
		NULL, &(conf->exfscount), &(l->exfslist), 0)) return -1;
	if(get_conf_val(field, value, "timer_script", &(conf->timer_script)))
		return -1;
	if(get_conf_val_args(field, value, "timer_arg", &(conf->timer_arg),
		&(l->got_timer_args), &(conf->tacount),
		&(l->talist), 0)) return -1;
	if(get_conf_val(field, value, "notify_success_script",
		&(conf->notify_success_script))) return -1;
	if(get_conf_val_args(field, value, "notify_success_arg",
		&(conf->notify_success_arg),
		&(l->got_ns_args), &(conf->nscount),
		&(l->nslist), 0)) return -1;
	if(get_conf_val(field, value, "notify_failure_script",
		&(conf->notify_failure_script))) return -1;
	if(get_conf_val_args(field, value, "notify_failure_arg",
		&(conf->notify_failure_arg), &(l->got_nf_args),
		&(conf->nfcount), &(l->nflist), 0)) return -1;
	if(get_conf_val(field, value, "backup_script_pre",
		&(conf->backup_script_pre))) return -1;
	if(get_conf_val_args(field, value, "backup_script_pre_arg",
		&(conf->backup_script_pre_arg), NULL, &(conf->bprecount),
		&(l->bprelist), 0)) return -1;
	if(get_conf_val(field, value, "backup_script_post",
		&(conf->backup_script_post))) return -1;
	if(get_conf_val_args(field, value, "backup_script_post_arg",
		&(conf->backup_script_post_arg), NULL, &(conf->bpostcount),
		&(l->bpostlist), 0)) return -1;
	if(get_conf_val(field, value, "restore_script_pre",
		&(conf->restore_script_pre))) return -1;
	if(get_conf_val_args(field, value, "restore_script_pre_arg",
		&(conf->restore_script_pre_arg), NULL, &(conf->rprecount),
		&(l->rprelist), 0)) return -1;
	if(get_conf_val(field, value, "restore_script_post",
		&(conf->restore_script_post))) return -1;
	if(get_conf_val_args(field, value, "restore_script_post_arg",
		&(conf->restore_script_post_arg), NULL, &(conf->rpostcount),
		&(l->rpostlist), 0)) return -1;

	if(get_conf_val(field, value, "server_script_pre",
		&(conf->server_script_pre))) return -1;
	if(get_conf_val_args(field, value, "server_script_pre_arg",
		&(conf->server_script_pre_arg), &(l->got_spre_args),
		&(conf->sprecount), &(l->sprelist), 0)) return -1;
	if(get_conf_val(field, value, "server_script_post",
		&(conf->server_script_post))) return -1;
	if(get_conf_val_args(field, value, "server_script_post_arg",
		&(conf->server_script_post_arg), &(l->got_spost_args),
		&(conf->spostcount), &(l->spostlist), 0)) return -1;

	if(get_conf_val(field, value, "backup_script", &(conf->backup_script)))
		return -1;
	if(get_conf_val_args(field, value, "backup_script_arg",
		&(conf->backup_script_arg), NULL, &(conf->bscount),
		&(l->bslist), 0)) return -1;
	if(get_conf_val(field, value, "restore_script",
		&(conf->restore_script))) return -1;
	if(get_conf_val_args(field, value, "restore_script_arg",
		&(conf->restore_script_arg), NULL, &(conf->rscount),
		&(l->rslist), 0)) return -1;
	if(get_conf_val(field, value, "server_script",
		&(conf->server_script))) return -1;
	if(get_conf_val_args(field, value, "server_script_arg",
		&(conf->server_script_arg), &(l->got_ss_args),
		&(conf->sscount), &(l->sslist), 0)) return -1;

	if(get_conf_val(field, value, "dedup_group", &(conf->dedup_group)))
		return -1;

	return 0;
}

static int load_config_field_and_value(struct config *conf, const char *field, const char *value, struct llists *l, const char *config_path, int line)
{
	if(!strcmp(field, "mode"))
	{
		if(!strcmp(value, "server")) conf->mode=MODE_SERVER;
		else if(!strcmp(value, "client")) conf->mode=MODE_CLIENT;
		else return -1;
	}
	else if(!strcmp(field, "compression"))
	{
		const char *cp=NULL;
		cp=value;
		if(!strncmp(value, "gzip", strlen("gzip")))
			cp=value+strlen("gzip");
		if(strlen(cp)!=1 || !isdigit(*cp))
			return -1;

		conf->compression=atoi(cp);
	}
	else if(!strcmp(field, "umask"))
	{
		conf->umask=strtol(value, NULL, 8);
	}
	else if(!strcmp(field, "ratelimit"))
	{
		float f=0;
		f=atof(value);
		// User is specifying Mega bits per second.
		// Need to convert to bytes per second.
		f=(f*1024*1024)/8;
		if(!f)
		{
			logp("ratelimit should be greater than zero\n");
			return -1;
		}
		conf->ratelimit=f;
	}
	else if(!strcmp(field, "min_file_size"))
	{
		if(get_file_size(value, &(conf->min_file_size),
			config_path, line)) return -1;
	}
	else if(!strcmp(field, "max_file_size"))
	{
		if(get_file_size(value, &(conf->max_file_size),
			config_path, line)) return -1;
	}
	else
	{
		if(load_config_ints(conf, field, value))
			return -1;
		if(load_config_strings(conf, field, value, l))
			return -1;
	}
	return 0;
}

/* Recursing, so need to define load_config_lines ahead of parse_config_line.
*/
int load_config_lines(const char *config_path, struct config *conf, struct llists *l);

static int parse_config_line(struct config *conf, struct llists *l, const char *config_path, char buf[], int line)
{
	char *field=NULL;
	char *value=NULL;

	if(!strncmp(buf, ". ", 2))
	{
		// The conf file specifies another file to include.
		char *np=NULL;
		char *extrafile=NULL;

		if(!(extrafile=strdup(buf+2)))
		{
			logp("out of memory\n");
			return -1;
		}

		if((np=strrchr(extrafile, '\n'))) *np='\0';
		if(!*extrafile)
		{
			free(extrafile);
			return -1;
		}

#ifdef HAVE_WIN32
		if(strlen(extrafile)>2
		  && extrafile[1]!=':')
#else
		if(*extrafile!='/')
#endif
		{
			// It is relative to the directory that the
			// current config file is in.
			char *cp=NULL;
			char *copy=NULL;
			char *tmp=NULL;
			if(!(copy=strdup(config_path)))
			{
				logp("out of memory\n");
				free(extrafile);
				return -1;
			}
			if((cp=strrchr(copy, '/'))) *cp='\0';
			if(!(tmp=prepend_s(copy,
				extrafile, strlen(extrafile))))
			{
				logp("out of memory\n");
				free(extrafile);
				free(copy);
			}
			free(extrafile);
			free(copy);
			extrafile=tmp;
		}

		if(load_config_lines(extrafile, conf, l))
		{
			free(extrafile);
			return -1;
		}
		free(extrafile);
		return 0;
	}

	if(config_get_pair(buf, &field, &value)) return -1;
	if(!field || !value) return 0;

	if(load_config_field_and_value(conf,
		field, value, l, config_path, line))
			return -1;
	return 0;
}

static void conf_problem(const char *config_path, const char *msg, int *r)
{
	logp("%s: %s\n", config_path, msg);
	(*r)--;
}

static int server_conf_checks(struct config *conf, const char *path, int *r)
{
	if(!conf->directory)
		conf_problem(path, "directory unset", r);
	if(!conf->clientconfdir)
		conf_problem(path, "clientconfdir unset", r);
	if(!conf->working_dir_recovery_method
	  || (strcmp(conf->working_dir_recovery_method, "delete")
	   && strcmp(conf->working_dir_recovery_method, "resume")
	   && strcmp(conf->working_dir_recovery_method, "use")))
		conf_problem(path, "unknown working_dir_recovery_method", r);
	if(!conf->ssl_cert)
		conf_problem(path, "ssl_cert unset", r);
	if(!conf->ssl_cert_ca)
		conf_problem(path, "ssl_cert_ca unset", r);
	if(!conf->ssl_dhfile)
		conf_problem(path, "ssl_dhfile unset", r);
	if(conf->encryption_password)
		conf_problem(path,
		  "encryption_password should not be set on the server!", r);
	if(!conf->status_port) // carry on if not set.
		logp("%s: status_port unset", path);
	if(!conf->max_children)
	{
		logp("%s: max_children unset - using 5\n", path);
		conf->max_children=5;
	}
	if(!conf->max_status_children)
	{
		logp("%s: max_status_children unset - using 5\n", path);
		conf->max_status_children=5;
	}
	if(!conf->kpcount)
		conf_problem(path, "keep unset", r);
	if(conf->max_hardlinks<2)
		conf_problem(path, "max_hardlinks too low", r);
	if(conf->max_children<=0)
		conf_problem(path, "max_children too low", r);
	if(conf->max_status_children<=0)
		conf_problem(path, "max_status_children too low", r);
	if(conf->max_storage_subdirs<=1000)
		conf_problem(path, "max_storage_subdirs too low", r);
	if(conf->ca_conf)
	{
		int ca_err=0;
		if(!conf->ca_name)
		{
			logp("ca_conf set, but ca_name not set\n");
			ca_err++;
		}
		if(!conf->ca_server_name)
		{
			logp("ca_conf set, but ca_server_name not set\n");
			ca_err++;
		}
		if(!conf->ca_burp_ca)
		{
			logp("ca_conf set, but ca_burp_ca not set\n");
			ca_err++;
		}
		if(!conf->ssl_dhfile)
		{
			logp("ca_conf set, but ssl_dhfile not set\n");
			ca_err++;
		}
		if(!conf->ssl_cert_ca)
		{
			logp("ca_conf set, but ssl_cert_ca not set\n");
			ca_err++;
		}
		if(!conf->ssl_cert)
		{
			logp("ca_conf set, but ssl_cert not set\n");
			ca_err++;
		}
		if(!conf->ssl_key)
		{
			logp("ca_conf set, but ssl_key not set\n");
			ca_err++;
		}
		if(ca_err) return -1;
	}

	return 0;
}

static int client_conf_checks(struct config *conf, const char *path, int *r)
{
	if(!conf->cname)
		conf_problem(path, "client name unset", r);
	if(!conf->password)
		conf_problem(path, "password unset", r);
	if(!conf->server)
		conf_problem(path, "server unset", r);
	if(!conf->ssl_cert)
		conf_problem(path, "ssl_cert unset", r);
	if(!conf->ssl_cert_ca)
		conf_problem(path, "ssl_cert_ca unset", r);
	if(!conf->ssl_peer_cn)
	{
		logp("ssl_peer_cn unset\n");
		if(conf->server)
		{
			logp("falling back to '%s'\n", conf->server);
			if(!(conf->ssl_peer_cn=strdup(conf->server)))
			{
				logp("out of memory\n");
				return -1;
			}
		}
	}
	if(!conf->lockfile)
		conf_problem(path, "lockfile unset", r);
	if(conf->autoupgrade_os
	  && strstr(conf->autoupgrade_os, ".."))
		conf_problem(path,
			"autoupgrade_os must not contain a '..' component", r);
	if(conf->ca_burp_ca)
	{
	  if(!conf->ca_csr_dir)
	   conf_problem(path, "ca_burp_ca set, but ca_csr_dir not set\n", r);
	  if(!conf->ssl_cert_ca)
	   conf_problem(path, "ca_burp_ca set, but ssl_cert_ca not set\n", r);
	  if(!conf->ssl_cert)
	   conf_problem(path, "ca_burp_ca set, but ssl_cert not set\n", r);
	  if(!conf->ssl_key)
	   conf_problem(path, "ca_burp_ca set, but ssl_key not set\n", r);
	}

	if(!r)
	{
		logp("Listing configured paths:\n");
		for(int b=0; b<conf->iecount; b++)
			logp("%s: %s\n",
				conf->incexcdir[b]->flag?
					"include":"exclude",
				conf->incexcdir[b]->path);
		logp("Listing starting paths:\n");
		for(int b=0; b<conf->sdcount; b++)
			logp("%s\n", conf->startdir[b]->path);
	}
	return 0;
}

static int finalise_config(const char *config_path, struct config *conf, struct llists *l, bool loadall)
{
	int i=0;
	int r=0;
	struct strlist **sdlist=NULL;

	// Set the strlist flag for the excluded fstypes
	for(i=0; i<conf->exfscount; i++)
	{
		l->exfslist[i]->flag=0;
		if(!strncasecmp(l->exfslist[i]->path, "0x", 2))
		{
			l->exfslist[i]->flag=strtol((l->exfslist[i]->path)+2,
				NULL, 16);
			logp("Excluding file system type 0x%08X\n",
				l->exfslist[i]->flag);
		}
		else
		{
			if(fstype_to_flag(l->exfslist[i]->path,
				&(l->exfslist[i]->flag)))
			{
				logp("Unknown exclude fs type: %s\n",
					l->exfslist[i]->path);
				return -1;
			}
		}
	}

	// include extensions
	do_strlist_sort(l->inlist, conf->incount, &(conf->incext));
	// exclude extensions
	do_strlist_sort(l->exlist, conf->excount, &(conf->excext));
	// exclude filesystems
	do_strlist_sort(l->exfslist, conf->exfscount, &(conf->excfs));
	do_strlist_sort(l->fflist, conf->ffcount, &(conf->fifos));
	do_strlist_sort(l->fslist, conf->fscount, &(conf->fschgdir));
	do_strlist_sort(l->ielist, conf->iecount, &(conf->incexcdir));
	do_strlist_sort(l->nblist, conf->nbcount, &(conf->nobackup));

	// This decides which directories to start backing up, and which
	// are subdirectories which don't need to be started separately.
	for(i=0; i<conf->iecount; i++)
	{
		if(path_checks(l->ielist[i]->path)) r--;
		if(!i)
		{
			// ielist is sorted - the first entry is one that
			// can be backed up
			if(!l->ielist[i]->flag)
			{
				logp("Top level should not be an exclude: %s\n",
					l->ielist[i]->path);
				return -1;
			}
			if(strlist_add(&sdlist, &(conf->sdcount),
				l->ielist[i]->path, 1)) return -1;
			continue;
		}
		// Ensure that we do not backup the same directory twice.
		if(!strcmp(l->ielist[i]->path, l->ielist[i-1]->path))
		{
			logp("Directory appears twice in config: %s\n",
				l->ielist[i]->path);
			return -1;
		}
		// If it is not a subdirectory of the most recent start point,
		// we have found another start point.
		if(!is_subdir(sdlist[(conf->sdcount)-1]->path,
			l->ielist[i]->path))
		{
			if(strlist_add(&sdlist, &(conf->sdcount),
				l->ielist[i]->path, 1)) return -1;
		}
	}
	conf->startdir=sdlist;

	if(!l->got_kp_args)
	{
		unsigned long long mult=1;
		for(i=0; i<conf->kpcount; i++)
		{
			if(!(l->kplist[i]->flag=atoi(l->kplist[i]->path)))
			{
				logp("'keep' value cannot be set to '%s'\n",
					l->kplist[i]->path);
				return -1;
			}
			mult*=l->kplist[i]->flag;

			// An error if you try to keep backups every second
			// for 100 years.
			if(mult>52560000)
			{
				logp("Your 'keep' values are far too high. High enough to keep a backup every second for 10 years. Please lower them to something sensible.\n");
				return -1;
			}
		}
		// If more than one keep value is set, add one to the last one.
		// This is so that, for example, having set 7, 4, 6, then
		// a backup of age 7*4*6=168 or more is guaranteed to be kept.
		// Otherwise, only 7*4*5=140 would be guaranteed to be kept.
		if(conf->kpcount>1) l->kplist[i-1]->flag++;
		conf->keep=l->kplist;
	}

	pre_post_override(&(conf->backup_script),
		&(conf->backup_script_pre), &(conf->backup_script_post));
	pre_post_override(&(conf->restore_script),
		&(conf->restore_script_pre), &(conf->restore_script_post));
	pre_post_override(&(conf->server_script),
		&(conf->server_script_pre), &(conf->server_script_post));

	if(!l->got_timer_args) conf->timer_arg=l->talist;
	if(!l->got_ns_args) conf->notify_success_arg=l->nslist;
	if(!l->got_nf_args) conf->notify_failure_arg=l->nflist;
	if(!l->got_ss_args) conf->server_script_arg=l->sslist;

	setup_script_arg_override(l->bslist, conf->bscount,
		&(l->bprelist), &(l->bpostlist),
		&(conf->bprecount), &(conf->bpostcount));
	setup_script_arg_override(l->rslist, conf->rscount,
		&(l->rprelist), &(l->rpostlist),
		&(conf->rprecount), &(conf->rpostcount));
	setup_script_arg_override(conf->server_script_arg, conf->sscount,
		&(l->sprelist), &(l->spostlist),
		&(conf->sprecount), &(conf->spostcount));

	conf->backup_script_pre_arg=l->bprelist;
	conf->backup_script_post_arg=l->bpostlist;
	conf->restore_script_pre_arg=l->rprelist;
	conf->restore_script_post_arg=l->rpostlist;

	if(!l->got_spre_args) conf->server_script_pre_arg=l->sprelist;
	if(!l->got_spost_args) conf->server_script_post_arg=l->spostlist;

	if(!loadall) return 0;

	if(!conf->port) conf_problem(config_path, "port unset", &r);

	// Let the caller check the 'keep' value.

	if(!conf->ssl_key_password) conf->ssl_key_password=strdup("");

	switch(conf->mode)
	{
		case MODE_SERVER:
			if(server_conf_checks(conf, config_path, &r)) r--;
			break;
		case MODE_CLIENT:
			if(client_conf_checks(conf, config_path, &r)) r--;
			break;
		case MODE_UNSET:
		default:
			logp("%s: mode unset - need 'server' or 'client'\n",
				config_path);
			r--;
			break;
	}

	// If client_lockdir not set, use conf->directory.
	if(!conf->client_lockdir && conf->directory
	  && !(conf->client_lockdir=strdup(conf->directory)))
	{
		logp("out of memory\n");
		return -1;
	}

	return r;
}


int load_config_lines(const char *config_path, struct config *conf, struct llists *l)
{
	int line=0;
	FILE *fp=NULL;
	char buf[4096]="";

	if(!(fp=fopen(config_path, "r")))
	{
		logp("could not open '%s' for reading.\n", config_path);
		return -1;
	}
	while(fgets(buf, sizeof(buf), fp))
	{
		line++;
		if(parse_config_line(conf, l, config_path, buf, line))
			goto err;
	}
	if(fp) fclose(fp);
	return 0;
err:
	conf_error(config_path, line);
	if(fp) fclose(fp);
	return -1;
}

static void set_got_args(struct llists *l, struct config *conf)
{
	l->got_timer_args=conf->tacount;
	l->got_ns_args=conf->nscount;
	l->got_nf_args=conf->nfcount;
	l->got_kp_args=conf->kpcount;
	l->got_spre_args=conf->sprecount;
	l->got_spost_args=conf->spostcount;
	l->got_ss_args=conf->sscount;
}

int load_config(const char *config_path, struct config *conf, bool loadall)
{
	struct llists l;

	memset(&l, 0, sizeof(struct llists));
	set_got_args(&l, conf);

	//logp("in load_config\n");
	if(loadall)
	{
		if(conf->configfile) free(conf->configfile);
		if(!(conf->configfile=strdup(config_path)))
		{
			logp("out of memory\n");
			return -1;
		}
	}

	if(load_config_lines(config_path, conf, &l))
		return -1;

	return finalise_config(config_path, conf, &l, loadall);
}

/* The client runs this when the server overrides the incexcs. */
int parse_incexcs_buf(struct config *conf, const char *incexc)
{
	int ret=0;
	int line=0;
	char *tok=NULL;
	char *copy=NULL;
	struct llists l;
	memset(&l, 0, sizeof(struct llists));
	set_got_args(&l, conf);
	if(!(copy=strdup(incexc)))
	{
		logp("out of memory\n");
		return -1;
	}
	free_incexcs(conf);
	if(!(tok=strtok(copy, "\n")))
	{
		logp("unable to parse server incexc\n");
		free(copy);
		return -1;
	}
	do
	{
		line++;
		if(parse_config_line(conf, &l, "", tok, line))
		{
			ret=-1;
			break;
		}
	} while((tok=strtok(NULL, "\n")));
	free(copy);

	if(ret) return ret;
	return finalise_config("server override", conf, &l, FALSE);
}

/* The server runs this when parsing a restore file on the server. */
int parse_incexcs_path(struct config *conf, const char *path)
{
	free_incexcs(conf);
	return load_config(path, conf, FALSE);
}

static int set_global_str(char **dst, const char *src)
{
	if(src && !(*dst=strdup(src)))
	{
		logp("out of memory when setting global string\n");
		return -1;
	}
	return 0;
}

static int set_global_arglist(struct strlist ***dst, struct strlist **src, int *dstcount, int srccount)
{
	if(!*dst && src)
	{
		int i=0;
		struct strlist **list=NULL;
		for(i=0; i<srccount; i++)
		{
			if(strlist_add(&list, dstcount,
				src[i]->path, src[i]->flag)) return -1;
		}
		*dst=list;
	}
	return 0;
}

/* Remember to update the list in the man page when you change these.*/
int set_client_global_config(struct config *conf, struct config *cconf, const char *client)
{
	cconf->syslog=conf->syslog;
	cconf->hardlinked_archive=conf->hardlinked_archive;
	cconf->librsync=conf->librsync;
	cconf->compression=conf->compression;
	cconf->notify_success_warnings_only=conf->notify_success_warnings_only;
	cconf->server_script_post_run_on_fail=conf->server_script_post_run_on_fail;
	if(set_global_str(&(cconf->directory), conf->directory))
		return -1;
	if(set_global_str(&(cconf->working_dir_recovery_method),
		conf->working_dir_recovery_method)) return -1;
	if(set_global_str(&(cconf->timer_script), conf->timer_script))
		return -1;
	if(set_global_str(&(cconf->user), conf->user))
		return -1;
	if(set_global_str(&(cconf->group), conf->group))
		return -1;
	if(set_global_str(&(cconf->notify_success_script),
		conf->notify_success_script)) return -1;
	if(set_global_str(&(cconf->notify_failure_script),
		conf->notify_failure_script)) return -1;
	if(set_global_arglist(&(cconf->timer_arg), conf->timer_arg,
		&(cconf->tacount), conf->tacount)) return -1;
	if(set_global_arglist(&(cconf->notify_success_arg),
		conf->notify_success_arg,
		&(cconf->nscount), conf->nscount)) return -1;
	if(set_global_arglist(&(cconf->notify_failure_arg),
		conf->notify_failure_arg,
		&(cconf->nfcount), conf->nfcount)) return -1;
	if(set_global_arglist(&(cconf->keep),
		conf->keep,
		&(cconf->kpcount), conf->kpcount)) return -1;
	if(set_global_str(&(cconf->dedup_group), conf->dedup_group))
		return -1;
	if(set_global_str(&(cconf->server_script_pre),
		conf->server_script_pre)) return -1;
	if(set_global_arglist(&(cconf->server_script_pre_arg),
		conf->server_script_pre_arg,
		&(cconf->sprecount), conf->sprecount)) return -1;
	if(set_global_str(&(cconf->server_script_post),
		conf->server_script_post)) return -1;
	if(set_global_arglist(&(cconf->server_script_post_arg),
		conf->server_script_post_arg,
		&(cconf->spostcount), conf->spostcount)) return -1;
	if(set_global_str(&(cconf->server_script),
		conf->server_script)) return -1;
	if(set_global_arglist(&(cconf->server_script_arg),
		conf->server_script_arg,
		&(cconf->sscount), conf->sscount)) return -1;

	// If ssl_peer_cn is not set, default it to the client name.
	if(!conf->ssl_peer_cn
	  && set_global_str(&(cconf->ssl_peer_cn), client))
		return -1;

	return 0;
}
