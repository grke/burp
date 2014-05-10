#include "include.h"
#include "glob_windows.h"

struct conf *conf_alloc(void)
{
	return (struct conf *)calloc_w(1, sizeof(struct conf), __func__);
}

/* Init only stuff related to includes/excludes.
   This is so that the server can override them all on the client. */
// FIX THIS: Maybe have this as a substructure of a struct conf.
// Could then just memset them all to zero here.
static void init_incexcs(struct conf *c)
{
	c->startdir=NULL;
	c->incexcdir=NULL;
	c->fschgdir=NULL;
	c->nobackup=NULL;
	c->incext=NULL; // include extensions
	c->excext=NULL; // exclude extensions
	c->increg=NULL; // include (regular expression)
	c->excreg=NULL; // include (regular expression)
	c->excfs=NULL; // exclude filesystems
	c->excom=NULL; // exclude from compression
	c->incglob=NULL; // exclude from compression
	c->fifos=NULL;
	c->blockdevs=NULL;
	c->split_vss=0;
	c->strip_vss=0;
	c->vss_drives=NULL;
	c->atime=0;
	/* stuff to do with restore */
	c->overwrite=0;
	c->strip=0;
	c->backup=NULL;
	c->restoreprefix=NULL;
	c->regex=NULL;
}

/* Free only stuff related to includes/excludes.
   This is so that the server can override them all on the client. */
static void free_incexcs(struct conf *c)
{
	strlists_free(&c->startdir);
	strlists_free(&c->incexcdir);
	strlists_free(&c->fschgdir);
	strlists_free(&c->nobackup);
	strlists_free(&c->incext); // include extensions
	strlists_free(&c->excext); // exclude extensions
	strlists_free(&c->increg); // include (regular expression)
	strlists_free(&c->excreg); // exclude (regular expression)
	strlists_free(&c->excfs); // exclude filesystems
	strlists_free(&c->excom); // exclude from compression
	strlists_free(&c->incglob); // include (glob)
	strlists_free(&c->fifos);
	strlists_free(&c->blockdevs);
	if(c->backup) free(c->backup);
	if(c->restoreprefix) free(c->restoreprefix);
	if(c->regex) free(c->regex);
	if(c->vss_drives) free(c->vss_drives);
	init_incexcs(c);
}

void conf_init(struct conf *c)
{
	// Set everything to 0.
	memset(c, 0, sizeof(struct conf));

	// Turn on defaults that are non-zero.
	c->forking=1;
	c->daemon=1;
	c->directory_tree=1;
	c->password_check=1;
	c->log_to_stdout=1;
	c->network_timeout=60*60*2; // two hours
	// ext3 maximum number of subdirs is 32000, so leave a little room.
	c->max_storage_subdirs=30000;
	c->librsync=1;
	c->compression=9;
	c->ssl_compression=5;
	c->version_warn=1;
	c->resume_partial=0;
	c->umask=0022;
	c->max_hardlinks=10000;

	c->client_can_delete=1;
	c->client_can_force_backup=1;
	c->client_can_list=1;
	c->client_can_restore=1;
	c->client_can_verify=1;

	c->server_can_restore=1;

	rconf_init(&c->rconf);
}

void conf_free_content(struct conf *c)
{
	if(!c) return;
	if(c->port) free(c->port);
	if(c->conffile) free(c->conffile);
	if(c->clientconfdir) free(c->clientconfdir);
	if(c->cname) free(c->cname);
	if(c->peer_version) free(c->peer_version);
	if(c->directory) free(c->directory);
	if(c->timestamp_format) free(c->timestamp_format);
	if(c->ca_conf) free(c->ca_conf);
	if(c->ca_name) free(c->ca_name);
	if(c->ca_server_name) free(c->ca_server_name);
	if(c->ca_burp_ca) free(c->ca_burp_ca);
	if(c->ca_csr_dir) free(c->ca_csr_dir);
	if(c->lockfile) free(c->lockfile);
	if(c->password) free(c->password);
	if(c->passwd) free(c->passwd);
	if(c->server) free(c->server);
 	if(c->recovery_method) free(c->recovery_method);
 	if(c->ssl_cert_ca) free(c->ssl_cert_ca);
        if(c->ssl_cert) free(c->ssl_cert);
        if(c->ssl_key) free(c->ssl_key);
        if(c->ssl_key_password) free(c->ssl_key_password);
        if(c->ssl_ciphers) free(c->ssl_ciphers);
        if(c->ssl_dhfile) free(c->ssl_dhfile);
        if(c->ssl_peer_cn) free(c->ssl_peer_cn);
        if(c->user) free(c->user);
        if(c->group) free(c->group);
        if(c->encryption_password) free(c->encryption_password);
	if(c->client_lockdir) free(c->client_lockdir);
	if(c->autoupgrade_dir) free(c->autoupgrade_dir);
	if(c->autoupgrade_os) free(c->autoupgrade_os);
	if(c->manual_delete) free(c->manual_delete);

	if(c->timer_script) free(c->timer_script);
	strlists_free(&c->timer_arg);

	if(c->n_success_script) free(c->n_success_script);
	strlists_free(&c->n_success_arg);

	if(c->n_failure_script) free(c->n_failure_script);
	strlists_free(&c->n_failure_arg);

	strlists_free(&c->rclients);

	if(c->b_script_pre) free(c->b_script_pre);
	strlists_free(&c->b_script_pre_arg);
	if(c->b_script_post) free(c->b_script_post);
	strlists_free(&c->b_script_post_arg);
	if(c->r_script_pre) free(c->r_script_pre);
	strlists_free(&c->r_script_pre_arg);
	if(c->r_script_post) free(c->r_script_post);
	strlists_free(&c->r_script_post_arg);

	if(c->s_script_pre) free(c->s_script_pre);
	strlists_free(&c->s_script_pre_arg);
	if(c->s_script_post) free(c->s_script_post);
	strlists_free(&c->s_script_post_arg);

	if(c->b_script) free(c->b_script);
	if(c->r_script) free(c->r_script);
	strlists_free(&c->b_script_arg);
	strlists_free(&c->r_script_arg);

	if(c->s_script) free(c->s_script);
	strlists_free(&c->s_script_arg);

	strlists_free(&c->keep);

	if(c->dedup_group) free(c->dedup_group);
	if(c->browsefile) free(c->browsefile);
	if(c->browsedir) free(c->browsedir);
	if(c->restore_spool) free(c->restore_spool);
	if(c->restore_client) free(c->restore_client);
	if(c->restore_path) free(c->restore_path);
	if(c->orig_client) free(c->orig_client);

	free_incexcs(c);

	conf_init(c);
}

void conf_free(struct conf *c)
{
	if(!c) return;
	conf_free_content(c);
	free(c);
}

// Get configuration value.
static int gcv(const char *f, const char *v, const char *want, char **dest)
{
	if(strcmp(f, want)) return 0;
	if(*dest) free(*dest);
	if(!(*dest=strdup_w(v, __func__))) return -1;
	return 0;
}

// Get configuration value integer.
static void gcv_int(const char *f, const char *v, const char *want, int *dest)
{
	if(!strcmp(f, want)) *dest=atoi(v);
}

// Get configuration value 8 bit integer.
static void gcv_uint8(const char *f, const char *v,
	const char *want, uint8_t *dest)
{
	if(!strcmp(f, want)) *dest=(uint8_t)atoi(v);
}

// Get field and value pair.
int conf_get_pair(char buf[], char **f, char **v)
{
	char *cp=NULL;
	char *eq=NULL;
	char *end=NULL;

	// strip leading space
	for(cp=buf; *cp && isspace(*cp); cp++) { }
	if(!*cp || *cp=='#')
	{
		*f=NULL;
		*v=NULL;
		return 0;
	}
	*f=cp;
	if(!(eq=strchr(*f, '='))) return -1;
	*eq='\0';

	// strip white space from before the equals sign
	for(cp=eq-1; *cp && isspace(*cp); cp--) *cp='\0';
	// skip white space after the equals sign
	for(cp=eq+1; *cp && isspace(*cp); cp++) { }
	*v=cp;
	// strip white space at the end of the line
	for(cp+=strlen(cp)-1; *cp && isspace(*cp); cp--) { *cp='\0'; }
	// remove quotes from around the value.
	// TODO: Make this more sophisticated - it should understand escapes,
	// for example.
	cp=*v;
	end=cp+strlen(cp)-1;
	if((*cp=='\'' && *end=='\'')
	  || (*cp=='\"' && *end=='\"'))
	{
		*v=cp+1; 
		*end='\0';
	}

	if(!*f || !**f || !*v || !**v) return -1;

	return 0;
}

// Get configuration value args.
static int do_gcv_a(const char *f, const char *v,
	const char *opt, struct strlist **list, int include, int sorted)
{
	char *tmp=NULL;
	if(gcv(f, v, opt, &tmp)) return -1;
	if(!tmp) return 0;
	if(sorted)
	{
		if(strlist_add_sorted(list, tmp, include)) return -1;
	}
	else
	{
		if(strlist_add(list, tmp, include)) return -1;
	}
	free(tmp);
	return 0;
}

// Get configuration value args (unsorted).
static int gcv_a(const char *f, const char *v,
	const char *opt, struct strlist **list, int include)
{
	return do_gcv_a(f, v, opt, list, include, 0);
}

// Get configuration value args (sorted).
static int gcv_a_sort(const char *f, const char *v,
	const char *opt, struct strlist **list, int include)
{
	return do_gcv_a(f, v, opt, list, include, 1);
}

/* Windows users have a nasty habit of putting in backslashes. Convert them. */
#ifdef HAVE_WIN32
void convert_backslashes(char **path)
{
	char *p=NULL;
	for(p=*path; *p; p++) if(*p=='\\') *p='/';
}
#endif

static int path_checks(const char *path, const char *err_msg)
{
	const char *p=NULL;
	for(p=path; *p; p++)
	{
		if(*p!='.' || *(p+1)!='.') continue;
		if((p==path || *(p-1)=='/') && (*(p+2)=='/' || !*(p+2)))
		{
			logp(err_msg);
			return -1;
		}
	}
// This is being run on the server too, where you can enter paths for the
// clients, so need to allow windows style paths for windows and unix.
	if((!isalpha(*path) || *(path+1)!=':')
#ifndef HAVE_WIN32
	  // Windows does not need to check for unix style paths.
	  && *path!='/'
#endif
	)
	{
		logp(err_msg);
		return -1;
	}
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

static int conf_error(const char *conf_path, int line)
{
	logp("%s: parse error on line %d\n", conf_path, line);
	return -1;
}

static int get_file_size(const char *v, ssize_t *dest, const char *conf_path, int line)
{
	// Store in bytes, allow k/m/g.
	const char *cp=NULL;
	*dest=strtoul(v, NULL, 10);
	for(cp=v; *cp && (isspace(*cp) || isdigit(*cp)); cp++) { }
	if(tolower(*cp)=='k') *dest*=1024;
	else if(tolower(*cp)=='m') *dest*=1024*1024;
	else if(tolower(*cp)=='g') *dest*=1024*1024*1024;
	else if(!*cp || *cp=='b')
	{ }
	else
	{
		logp("Unknown file size type '%s' - please use b/kb/mb/gb\n",
			cp);
		return conf_error(conf_path, line);
	}
	return 0;
}

int conf_val_reset(const char *src, char **dest)
{
	if(!src) return 0;
	if(dest && *dest) free(*dest);
	if(!(*dest=strdup_w(src, __func__))) return -1;
	return 0;
}

static int pre_post_override(char **override, char **pre, char **post)
{
	if(!override || !*override) return 0;
	if(conf_val_reset(*override, pre)
	  || conf_val_reset(*override, post))
		return -1;
	free(*override);
	*override=NULL;
	return 0;
}

/*
static int setup_script_arg_override(struct strlist *list, struct strlist **prelist, struct strlist **postlist)
{
	struct strlist *l;
	if(!list) return 0;
	strlists_free(prelist);
	strlists_free(postlist);
	for(l=list; l; l=l->next)
	{
		if(strlist_add(prelist, l->path, 0)
		  || strlist_add(postlist, l->path, 0))
			return -1;
	}
	return 0;
}
*/

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
	{ "devtmpfs",		0x00009FA0 },
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
/* Use this C code to figure out what f_type gets set to.
#include <stdio.h>
#include <sys/vfs.h>

int main(int argc, char *argv[])
{
        int i=0;
        struct statfs buf;
        if(argc<1)
        {
                printf("not enough args\n");
                return -1;
        }
        if(statfs(argv[1], &buf))
        {
                printf("error\n");
                return -1;
        }
        printf("0x%08X\n", buf.f_type);
        return 0;
}
*/

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

static int load_conf_ints(struct conf *c,
	const char *f, // field
	const char *v) //value
{
	gcv_uint8(f, v, "syslog", &(c->log_to_syslog));
	gcv_uint8(f, v, "stdout", &(c->log_to_stdout));
	gcv_uint8(f, v, "progress_counter", &(c->progress_counter));
	gcv_uint8(f, v, "hardlinked_archive", &(c->hardlinked_archive));
	gcv_int(f, v, "max_hardlinks", &(c->max_hardlinks));
	gcv_uint8(f, v, "librsync", &(c->librsync));
	gcv_uint8(f, v, "version_warn", &(c->version_warn));
	gcv_uint8(f, v, "resume_partial", &(c->resume_partial));
	gcv_uint8(f, v, "cross_all_filesystems", &(c->cross_all_filesystems));
	gcv_uint8(f, v, "read_all_fifos", &(c->read_all_fifos));
	gcv_uint8(f, v, "read_all_blockdevs", &(c->read_all_blockdevs));
	gcv_uint8(f, v, "backup_script_post_run_on_fail",
					&(c->b_script_post_run_on_fail));
	gcv_uint8(f, v, "server_script_post_run_on_fail",
					&(c->s_script_post_run_on_fail));
	gcv_uint8(f, v, "server_script_pre_notify",
					&(c->s_script_pre_notify));
	gcv_uint8(f, v, "server_script_post_notify",
					&(c->s_script_post_notify));
	gcv_uint8(f, v, "server_script_notify", &(c->s_script_notify));
	gcv_uint8(f, v, "notify_success_warnings_only",
					&(c->n_success_warnings_only));
	gcv_uint8(f, v, "notify_success_changes_only",
					&(c->n_success_changes_only));
	gcv_int(f, v, "network_timeout", &(c->network_timeout));
	gcv_int(f, v, "max_children", &(c->max_children));
	gcv_int(f, v, "max_status_children", &(c->max_status_children));
	gcv_int(f, v, "max_storage_subdirs", &(c->max_storage_subdirs));
	gcv_uint8(f, v, "overwrite", &(c->overwrite));
	gcv_uint8(f, v, "split_vss", &(c->split_vss));
	gcv_uint8(f, v, "strip_vss", &(c->strip_vss));
	gcv_uint8(f, v, "atime", &(c->atime));
	gcv_int(f, v, "strip", &(c->strip));
	gcv_uint8(f, v, "fork", &(c->forking));
	gcv_uint8(f, v, "daemon", &(c->daemon));
	gcv_uint8(f, v, "directory_tree", &(c->directory_tree));
	gcv_uint8(f, v, "client_can_delete", &(c->client_can_delete));
	gcv_uint8(f, v, "client_can_force_backup",
					&(c->client_can_force_backup));
	gcv_uint8(f, v, "client_can_list", &(c->client_can_list));
	gcv_uint8(f, v, "client_can_restore", &(c->client_can_restore));
	gcv_uint8(f, v, "client_can_verify", &(c->client_can_verify));
	gcv_uint8(f, v, "server_can_restore", &(c->server_can_restore));
	gcv_uint8(f, v, "password_check", &(c->password_check));

	return 0;
}

static int load_conf_strings(struct conf *c,
	const char *f, // field
	const char *v  // value
	)
{
	if(  gcv(f, v, "port", &(c->port))
	  || gcv(f, v, "status_port", &(c->status_port))
	  || gcv(f, v, "ssl_cert_ca", &(c->ssl_cert_ca))
	  || gcv(f, v, "ssl_cert", &(c->ssl_cert))
	  || gcv(f, v, "ssl_key", &(c->ssl_key))
	// ssl_cert_password is a synonym for ssl_key_password
	  || gcv(f, v, "ssl_cert_password", &(c->ssl_key_password))
	  || gcv(f, v, "ssl_key_password", &(c->ssl_key_password))
	  || gcv(f, v, "ssl_dhfile", &(c->ssl_dhfile))
	  || gcv(f, v, "ssl_peer_cn", &(c->ssl_peer_cn))
	  || gcv(f, v, "ssl_ciphers", &(c->ssl_ciphers))
	  || gcv(f, v, "clientconfdir", &(c->clientconfdir))
	  || gcv(f, v, "cname", &(c->cname))
	  || gcv(f, v, "directory", &(c->directory))
	  || gcv(f, v, "timestamp_format", &(c->timestamp_format))
	  || gcv(f, v, "ca_conf", &(c->ca_conf))
	  || gcv(f, v, "ca_name", &(c->ca_name))
	  || gcv(f, v, "ca_server_name", &(c->ca_server_name))
	  || gcv(f, v, "ca_burp_ca", &(c->ca_burp_ca))
	  || gcv(f, v, "ca_csr_dir", &(c->ca_csr_dir))
	  || gcv(f, v, "backup", &(c->backup))
	  || gcv(f, v, "restoreprefix", &(c->restoreprefix))
	  || gcv(f, v, "regex", &(c->regex))
	  || gcv(f, v, "vss_drives", &(c->vss_drives))
	  || gcv(f, v, "browsedir", &(c->browsedir))
	  || gcv(f, v, "browsefile", &(c->browsefile))
	  || gcv(f, v, "manual_delete", &(c->manual_delete))
	  || gcv(f, v, "restore_spool", &(c->restore_spool))
	  || gcv(f, v, "working_dir_recovery_method", &(c->recovery_method))
	  || gcv(f, v, "autoupgrade_dir", &(c->autoupgrade_dir))
	  || gcv(f, v, "autoupgrade_os", &(c->autoupgrade_os))
	  || gcv(f, v, "lockfile", &(c->lockfile))
	// "pidfile" is a synonym for "lockfile".
	  || gcv(f, v, "pidfile", &(c->lockfile))
	  || gcv(f, v, "password", &(c->password))
	  || gcv(f, v, "passwd", &(c->passwd))
	  || gcv(f, v, "server", &(c->server))
	  || gcv(f, v, "user", &(c->user))
	  || gcv(f, v, "group", &(c->group))
	  || gcv(f, v, "client_lockdir", &(c->client_lockdir))
	  || gcv(f, v, "encryption_password", &(c->encryption_password))
	  || gcv_a(f, v, "keep", &c->keep, 1)
	  || gcv_a_sort(f, v, "include", &c->incexcdir, 1)
	  || gcv_a_sort(f, v, "exclude", &c->incexcdir, 0)
	  || gcv_a_sort(f, v, "cross_filesystem", &c->fschgdir, 0)
	  || gcv_a_sort(f, v, "nobackup", &c->nobackup, 0)
	  || gcv_a_sort(f, v, "read_fifo", &c->fifos, 0)
	  || gcv_a_sort(f, v, "read_blockdev", &c->blockdevs, 0)
	  || gcv_a_sort(f, v, "include_ext", &c->incext, 0)
	  || gcv_a_sort(f, v, "exclude_ext", &c->excext, 0)
	  || gcv_a_sort(f, v, "include_regex", &c->increg, 0)
	  || gcv_a_sort(f, v, "exclude_regex", &c->excreg, 0)
	  || gcv_a_sort(f, v, "include_glob", &c->incglob, 0)
	  || gcv_a_sort(f, v, "exclude_fs", &c->excfs, 0)
	  || gcv_a_sort(f, v, "exclude_comp", &c->excom, 0)
	  || gcv(f, v, "timer_script", &(c->timer_script))
	  || gcv_a(f, v, "timer_arg", &(c->timer_arg), 0)
	  || gcv(f, v, "notify_success_script", &(c->n_success_script))
	  || gcv_a(f, v, "notify_success_arg", &(c->n_success_arg), 0)
	  || gcv(f, v, "notify_failure_script", &(c->n_failure_script))
	  || gcv_a(f, v, "notify_failure_arg", &(c->n_failure_arg), 0)
	  || gcv(f, v, "backup_script_pre", &(c->b_script_pre))
	  || gcv_a(f, v, "backup_script_pre_arg", &(c->b_script_pre_arg), 0)
	  || gcv(f, v, "backup_script_post", &(c->b_script_post))
	  || gcv_a(f, v, "backup_script_post_arg", &(c->b_script_post_arg), 0)
	  || gcv(f, v, "restore_script_pre", &(c->r_script_pre))
	  || gcv_a(f, v, "restore_script_pre_arg", &(c->r_script_pre_arg), 0)
	  || gcv(f, v, "restore_script_post", &(c->r_script_post))
	  || gcv_a(f, v, "restore_script_post_arg", &(c->r_script_post_arg), 0)
	  || gcv(f, v, "server_script_pre", &(c->s_script_pre))
	  || gcv_a(f, v, "server_script_pre_arg", &(c->s_script_pre_arg), 0)
	  || gcv(f, v, "server_script_post", &(c->s_script_post))
	  || gcv_a(f, v, "server_script_post_arg", &(c->s_script_post_arg), 0)
	  || gcv(f, v, "backup_script", &(c->b_script))
	  || gcv_a(f, v, "backup_script_arg", &(c->b_script_arg), 0)
	  || gcv(f, v, "restore_script", &(c->r_script))
	  || gcv_a(f, v, "restore_script_arg", &(c->r_script_arg), 0)
	  || gcv(f, v, "server_script", &(c->s_script))
	  || gcv_a(f, v, "server_script_arg", &(c->s_script_arg), 0)
	  || gcv_a_sort(f, v, "restore_client", &(c->rclients), 0)
	  || gcv(f, v, "dedup_group", &(c->dedup_group))
	  || gcv(f, v, "orig_client", &(c->orig_client)))
		return -1;

	return 0;
}

static int get_compression(const char *v)
{
	const char *cp=v;
	if(!strncmp(v, "gzip", strlen("gzip"))
	  || !(strncmp(v, "zlib", strlen("zlib"))))
		cp=v+strlen("gzip"); // Or "zlib".
	if(strlen(cp)==1 && isdigit(*cp))
		return atoi(cp);
	return -1;
}

static int load_conf_field_and_value(struct conf *c,
	const char *f, // field
	const char *v, // value
	const char *conf_path,
	int line)
{
	if(!strcmp(f, "mode"))
	{
		if(!strcmp(v, "server"))
		{
			c->mode=MODE_SERVER;
			c->progress_counter=0; // default to off for server
		}
		else if(!strcmp(v, "client"))
		{
			c->mode=MODE_CLIENT;
			c->progress_counter=1; // default to on for client
		}
		else return -1;
	}
	else if(!strcmp(f, "protocol"))
	{
		if(!strcmp(v, "0")) c->protocol=PROTO_AUTO;
		else if(!strcmp(v, "1")) c->protocol=PROTO_BURP1;
		else if(!strcmp(v, "2")) c->protocol=PROTO_BURP2;
		else return -1;
	}
	else if(!strcmp(f, "compression"))
	{
		if((c->compression=get_compression(v))<0)
			return -1;
	}
	else if(!strcmp(f, "ssl_compression"))
	{
		if((c->ssl_compression=get_compression(v))<0)
			return -1;
	}
	else if(!strcmp(f, "umask"))
	{
		c->umask=strtol(v, NULL, 8);
	}
	else if(!strcmp(f, "ratelimit"))
	{
		float f=0;
		f=atof(v);
		// User is specifying Mega bits per second.
		// Need to convert to bytes per second.
		f=(f*1024*1024)/8;
		if(!f)
		{
			logp("ratelimit should be greater than zero\n");
			return -1;
		}
		c->ratelimit=f;
	}
	else if(!strcmp(f, "min_file_size"))
	{
		if(get_file_size(v, &(c->min_file_size), conf_path, line))
			return -1;
	}
	else if(!strcmp(f, "max_file_size"))
	{
		if(get_file_size(v, &(c->max_file_size),
			conf_path, line)) return -1;
	}
	else
	{
		if(load_conf_ints(c, f, v)
		  || load_conf_strings(c, f, v))
			return -1;
	}
	return 0;
}

/* Recursing, so need to define load_conf_lines ahead of parse_conf_line.
*/
static int load_conf_lines(const char *conf_path, struct conf *c);

static int parse_conf_line(struct conf *c, const char *conf_path,
	char buf[], int line)
{
	char *f=NULL; // field
	char *v=NULL; // value

	if(!strncmp(buf, ". ", 2))
	{
		// The conf file specifies another file to include.
		char *np=NULL;
		char *extrafile=NULL;

		if(!(extrafile=strdup_w(buf+2, __func__))) return -1;

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
			// current conf file is in.
			char *cp=NULL;
			char *copy=NULL;
			char *tmp=NULL;
			if(!(copy=strdup_w(conf_path, __func__)))
			{
				free(extrafile);
				return -1;
			}
			if((cp=strrchr(copy, '/'))) *cp='\0';
			if(!(tmp=prepend_s(copy, extrafile)))
			{
				log_out_of_memory(__func__);
				free(extrafile);
				free(copy);
			}
			free(extrafile);
			free(copy);
			extrafile=tmp;
		}

		if(load_conf_lines(extrafile, c))
		{
			free(extrafile);
			return -1;
		}
		free(extrafile);
		return 0;
	}

	if(conf_get_pair(buf, &f, &v)) return -1;
	if(!f || !v) return 0;

	if(load_conf_field_and_value(c, f, v, conf_path, line))
		return -1;
	return 0;
}

static void conf_problem(const char *conf_path, const char *msg, int *r)
{
	logp("%s: %s\n", conf_path, msg);
	(*r)--;
}

static int server_conf_checks(struct conf *c, const char *path, int *r)
{
	if(!c->directory)
		conf_problem(path, "directory unset", r);
	if(!c->dedup_group)
		conf_problem(path, "dedup_group unset", r);
	else if(!c->timestamp_format
	  && !(c->timestamp_format=strdup_w("%Y-%m-%d %H:%M:%S", __func__)))
		return -1;
	if(!c->clientconfdir)
		conf_problem(path, "clientconfdir unset", r);
	if(!c->recovery_method
	  || (strcmp(c->recovery_method, "delete")
	   && strcmp(c->recovery_method, "resume")
	   && strcmp(c->recovery_method, "use")))
		conf_problem(path, "unknown working_dir_recovery_method", r);
	if(!c->ssl_cert)
		conf_problem(path, "ssl_cert unset", r);
	if(!c->ssl_cert_ca)
		conf_problem(path, "ssl_cert_ca unset", r);
	if(!c->ssl_dhfile)
		conf_problem(path, "ssl_dhfile unset", r);
	if(c->encryption_password)
		conf_problem(path,
		  "encryption_password should not be set on the server!", r);
	if(!c->status_port) // carry on if not set.
		logp("%s: status_port unset", path);
	if(!c->max_children)
	{
		logp("%s: max_children unset - using 5\n", path);
		c->max_children=5;
	}
	if(!c->max_status_children)
	{
		logp("%s: max_status_children unset - using 5\n", path);
		c->max_status_children=5;
	}
	if(!c->keep)
		conf_problem(path, "keep unset", r);
	if(c->max_hardlinks<2)
		conf_problem(path, "max_hardlinks too low", r);
	if(c->max_children<=0)
		conf_problem(path, "max_children too low", r);
	if(c->max_status_children<=0)
		conf_problem(path, "max_status_children too low", r);
	if(c->max_storage_subdirs<=1000)
		conf_problem(path, "max_storage_subdirs too low", r);
	if(c->ca_conf)
	{
		int ca_err=0;
		if(!c->ca_name)
		{
			logp("ca_conf set, but ca_name not set\n");
			ca_err++;
		}
		if(!c->ca_server_name)
		{
			logp("ca_conf set, but ca_server_name not set\n");
			ca_err++;
		}
		if(!c->ca_burp_ca)
		{
			logp("ca_conf set, but ca_burp_ca not set\n");
			ca_err++;
		}
		if(!c->ssl_dhfile)
		{
			logp("ca_conf set, but ssl_dhfile not set\n");
			ca_err++;
		}
		if(!c->ssl_cert_ca)
		{
			logp("ca_conf set, but ssl_cert_ca not set\n");
			ca_err++;
		}
		if(!c->ssl_cert)
		{
			logp("ca_conf set, but ssl_cert not set\n");
			ca_err++;
		}
		if(!c->ssl_key)
		{
			logp("ca_conf set, but ssl_key not set\n");
			ca_err++;
		}
		if(ca_err) return -1;
	}
	if(c->manual_delete)
	{
		if(path_checks(c->manual_delete,
			"ERROR: Please use an absolute manual_delete path.\n"))
				return -1;
	}

	return 0;
}

static int client_conf_checks(struct conf *c, const char *path, int *r)
{
	if(!c->cname)
		conf_problem(path, "client name unset", r);
	if(!c->password)
		conf_problem(path, "password unset", r);
	if(!c->server)
		conf_problem(path, "server unset", r);
	if(!c->ssl_cert)
		conf_problem(path, "ssl_cert unset", r);
	if(!c->ssl_cert_ca)
		conf_problem(path, "ssl_cert_ca unset", r);
	if(!c->ssl_peer_cn)
	{
		logp("ssl_peer_cn unset\n");
		if(c->server)
		{
			logp("falling back to '%s'\n", c->server);
			if(!(c->ssl_peer_cn=strdup_w(c->server, __func__)))
				return -1;
		}
	}
	if(!c->lockfile)
		conf_problem(path, "lockfile unset", r);
	if(c->autoupgrade_os
	  && strstr(c->autoupgrade_os, ".."))
		conf_problem(path,
			"autoupgrade_os must not contain a '..' component", r);
	if(c->ca_burp_ca)
	{
		if(!c->ca_csr_dir)
			conf_problem(path,
				"ca_burp_ca set, but ca_csr_dir not set\n", r);
		if(!c->ssl_cert_ca)
			conf_problem(path,
				"ca_burp_ca set, but ssl_cert_ca not set\n", r);
		if(!c->ssl_cert)
			conf_problem(path,
				"ca_burp_ca set, but ssl_cert not set\n", r);
		if(!c->ssl_key)
			conf_problem(path,
				"ca_burp_ca set, but ssl_key not set\n", r);
	}

	if(!r)
	{
		struct strlist *l;
		logp("Listing configured paths:\n");
		for(l=c->incexcdir; l; l=l->next)
			logp("%s: %s\n", l->flag?"include":"exclude", l->path);
		logp("Listing starting paths:\n");
		for(l=c->startdir; l; l=l->next)
			if(l->flag) logp("%s\n", l->path);
	}
	return 0;
}

static int finalise_keep_args(struct conf *c)
{
	struct strlist *k;
	struct strlist *last=NULL;
	unsigned long long mult=1;
	for(k=c->keep; k; k=k->next)
	{
		if(!(k->flag=atoi(k->path)))
		{
			logp("'keep' value cannot be set to '%s'\n", k->path);
			return -1;
		}
		mult*=k->flag;

		// An error if you try to keep backups every second
		// for 100 years.
		if(mult>52560000)
		{
			logp("Your 'keep' values are far too high. High enough to keep a backup every second for 10 years. Please lower them to something sensible.\n");
			return -1;
		}
		last=k;
	}
	// If more than one keep value is set, add one to the last one.
	// This is so that, for example, having set 7, 4, 6, then
	// a backup of age 7*4*6=168 or more is guaranteed to be kept.
	// Otherwise, only 7*4*5=140 would be guaranteed to be kept.
	if(c->keep && c->keep->next) last->flag++;
	return 0;
}

// This decides which directories to start backing up, and which
// are subdirectories which don't need to be started separately.
static int finalise_start_dirs(struct conf *c)
{
	struct strlist *s=NULL;
	struct strlist *last_ie=NULL;
	struct strlist *last_sd=NULL;

	for(s=c->incexcdir; s; s=s->next)
	{
#ifdef HAVE_WIN32
		convert_backslashes(&s->path);
#endif
		if(path_checks(s->path,
			"ERROR: Please use absolute include/exclude paths.\n"))
				return -1;
		
		if(!s->flag) continue; // an exclude

		// Ensure that we do not backup the same directory twice.
		if(last_ie && !strcmp(s->path, last_ie->path))
		{
			logp("Directory appears twice in conf: %s\n",
				s->path);
			return -1;
		}
		// If it is not a subdirectory of the most recent start point,
		// we have found another start point.
		if(!c->startdir
		  || !is_subdir(last_sd->path, s->path))
		{
			// Do not use strlist_add_sorted, because last_sd is
			// relying on incexcdir already being sorted.
			if(strlist_add(&c->startdir,s->path, s->flag))
				return -1;
			last_sd=s;
		}
		last_ie=s;
	}
	return 0;
}

// The glob stuff should only run on the client side.
static int finalise_glob(struct conf *c)
{
#ifdef HAVE_WIN32
	if(windows_glob(c)) return -1;
#else
	int i;
	glob_t globbuf;
	struct strlist *l;
	struct strlist *last=NULL;
	memset(&globbuf, 0, sizeof(globbuf));
	for(l=c->incglob; l; l=l->next)
	{
		glob(l->path, last?GLOB_APPEND:0, NULL, &globbuf);
		last=l;
	}

	for(i=0; (unsigned int)i<globbuf.gl_pathc; i++)
		strlist_add_sorted(&c->incexcdir, globbuf.gl_pathv[i], 1);

	globfree(&globbuf);
#endif
	return 0;
}

// Set the flag of the first item in a list that looks at extensions to the
// maximum number of characters that need to be checked, plus one. This is for
// a bit of added efficiency.
static void set_max_ext(struct strlist *list)
{
	int max=0;
	struct strlist *l=NULL;
	struct strlist *last=NULL;
	for(l=list; l; l=l->next)
	{
		int s=strlen(l->path);
		if(s>max) max=s;
		last=l;
	}
	if(last) last->flag=max+1;
}

static int finalise_fstypes(struct conf *c)
{
	struct strlist *l;
	// Set the strlist flag for the excluded fstypes
	for(l=c->excfs; l; l=l->next)
	{
		l->flag=0;
		if(!strncasecmp(l->path, "0x", 2))
		{
			l->flag=strtol((l->path)+2, NULL, 16);
			logp("Excluding file system type 0x%08X\n", l->flag);
		}
		else
		{
			if(fstype_to_flag(l->path, &(l->flag)))
			{
				logp("Unknown exclude fs type: %s\n", l->path);
				l->flag=0;
			}
		}
	}
	return 0;
}

static int conf_finalise(const char *conf_path, struct conf *c, uint8_t loadall)
{
	int r=0;

	if(finalise_fstypes(c)) return -1;

	strlist_compile_regexes(c->increg);
	strlist_compile_regexes(c->excreg);

	set_max_ext(c->incext);
	set_max_ext(c->excext);
	set_max_ext(c->excom);

	if(c->mode==MODE_CLIENT && finalise_glob(c)) return -1;

	if(finalise_start_dirs(c)) return -1;

	if(finalise_keep_args(c)) return -1;

	pre_post_override(&c->b_script, &c->b_script_pre, &c->b_script_post);
	pre_post_override(&c->r_script, &c->r_script_pre, &c->r_script_post);
	pre_post_override(&c->s_script, &c->s_script_pre, &c->s_script_post);
	if(c->s_script_notify)
	{
		c->s_script_pre_notify=c->s_script_notify;
		c->s_script_post_notify=c->s_script_notify;
	}
/*
	if(!c->timer_arg) c->timer_arg=l->talist;
	if(!c->n_success_arg) c->n_success_arg=l->nslist;
	if(!c->n_failure_arg) c->n_failure_arg=l->nflist;
	if(!c->server_script_arg) c->server_script_arg=l->sslist;
	if(!c->rclients) c->rclients=l->rclist;

	setup_script_arg_override(l->bslist, &l->bprelist, &l->bpostlist);
	setup_script_arg_override(l->rslist, &l->rprelist, &l->rpostlist);
	setup_script_arg_override(c->s_script_arg, &l->sprelist, &l->spostlist);

	c->b_script_pre_arg=l->bprelist;
	c->b_script_post_arg=l->bpostlist;
	c->r_script_pre_arg=l->rprelist;
	c->r_script_post_arg=l->rpostlist;

	if(!l->got_spre_args) c->s_script_pre_arg=l->sprelist;
	if(!l->got_spost_args) c->s_script_post_arg=l->spostlist;
*/

	if(!loadall) return 0;

	if(!c->port) conf_problem(conf_path, "port unset", &r);

	if(rconf_check(&c->rconf)) r--;

	// Let the caller check the 'keep' value.

	if(!c->ssl_key_password
	  && !(c->ssl_key_password=strdup_w("", __func__)))
		r--;

	switch(c->mode)
	{
		case MODE_SERVER:
			if(server_conf_checks(c, conf_path, &r)) r--;
			break;
		case MODE_CLIENT:
			if(client_conf_checks(c, conf_path, &r)) r--;
			break;
		case MODE_UNSET:
		default:
			logp("%s: mode unset - need 'server' or 'client'\n",
				conf_path);
			r--;
			break;
	}

	return r;
}


static int load_conf_lines(const char *conf_path, struct conf *c)
{
	int line=0;
	FILE *fp=NULL;
	char buf[4096]="";

	if(!(fp=fopen(conf_path, "r")))
	{
		logp("could not open '%s' for reading.\n", conf_path);
		return -1;
	}
	while(fgets(buf, sizeof(buf), fp))
	{
		line++;
		if(parse_conf_line(c, conf_path, buf, line))
			goto err;
	}
	if(fp) fclose(fp);
	return 0;
err:
	conf_error(conf_path, line);
	if(fp) fclose(fp);
	return -1;
}

int conf_load(const char *conf_path, struct conf *c, uint8_t loadall)
{
	//logp("in conf_load\n");
	if(loadall)
	{
		if(c->conffile) free(c->conffile);
		if(!(c->conffile=strdup_w(conf_path, __func__)))
			return -1;
	}

	if(load_conf_lines(conf_path, c))
		return -1;

	return conf_finalise(conf_path, c, loadall);
}

/* The client runs this when the server overrides the incexcs. */
int parse_incexcs_buf(struct conf *c, const char *incexc)
{
	int ret=0;
	int line=0;
	char *tok=NULL;
	char *copy=NULL;

	if(!incexc) return 0;
	
	if(!(copy=strdup_w(incexc, __func__))) return -1;
	free_incexcs(c);
	if(!(tok=strtok(copy, "\n")))
	{
		logp("unable to parse server incexc\n");
		free(copy);
		return -1;
	}
	do
	{
		line++;
		if(parse_conf_line(c, "", tok, line))
		{
			ret=-1;
			break;
		}
	} while((tok=strtok(NULL, "\n")));
	free(copy);

	if(ret) return ret;
	return conf_finalise("server override", c, 0);
}

int log_incexcs_buf(const char *incexc)
{
	char *tok=NULL;
	char *copy=NULL;
	if(!incexc || !*incexc) return 0;
	if(!(copy=strdup_w(incexc, __func__)))
		return -1;
	if(!(tok=strtok(copy, "\n")))
	{
		logp("unable to parse server incexc\n");
		free(copy);
		return -1;
	}
	do
	{
		logp("%s\n", tok);
	} while((tok=strtok(NULL, "\n")));
	free(copy);
	return 0;
}

/* The server runs this when parsing a restore file on the server. */
int parse_incexcs_path(struct conf *c, const char *path)
{
	free_incexcs(c);
	return conf_load(path, c, 0);
}

static int set_global_str(char **dst, const char *src)
{
	if(src && !(*dst=strdup_w(src, __func__)))
		return -1;
	return 0;
}

static int set_global_arglist(struct strlist **dst, struct strlist *src)
{
	struct strlist *s=NULL;
	// Not using strlist_add_sorted, as they should be set in the order
	// that they were first found.
	for(s=src; s; s=s->next)
		if(strlist_add(dst, s->path, s->flag))
			return -1;
	return 0;
}

/* Remember to update the list in the man page when you change these.*/
int conf_set_client_global(struct conf *c, struct conf *cc)
{
	cc->forking=c->forking;
	cc->protocol=c->protocol;
	cc->log_to_syslog=c->log_to_syslog;
	cc->log_to_stdout=c->log_to_stdout;
	cc->progress_counter=c->progress_counter;
	cc->password_check=c->password_check;
	cc->manual_delete=c->manual_delete;
	cc->client_can_delete=c->client_can_delete;
	cc->client_can_force_backup=c->client_can_force_backup;
	cc->client_can_list=c->client_can_list;
	cc->client_can_restore=c->client_can_restore;
	cc->client_can_verify=c->client_can_verify;
	cc->hardlinked_archive=c->hardlinked_archive;
	cc->librsync=c->librsync;
	cc->compression=c->compression;
	cc->version_warn=c->version_warn;
	cc->resume_partial=c->resume_partial;
	cc->n_success_warnings_only=c->n_success_warnings_only;
	cc->n_success_changes_only=c->n_success_changes_only;
	cc->s_script_post_run_on_fail=c->s_script_post_run_on_fail;
	cc->s_script_pre_notify=c->s_script_pre_notify;
	cc->s_script_post_notify=c->s_script_post_notify;
	cc->s_script_notify=c->s_script_notify;
	cc->directory_tree=c->directory_tree;
	if(set_global_str(&(cc->directory), c->directory))
		return -1;
	if(set_global_str(&(cc->timestamp_format), c->timestamp_format))
		return -1;
	if(set_global_str(&(cc->recovery_method),
		c->recovery_method)) return -1;
	if(set_global_str(&(cc->timer_script), c->timer_script))
		return -1;
	if(set_global_str(&(cc->user), c->user))
		return -1;
	if(set_global_str(&(cc->group), c->group))
		return -1;
	if(set_global_str(&(cc->n_success_script),
		c->n_success_script)) return -1;
	if(set_global_str(&(cc->n_failure_script),
		c->n_failure_script)) return -1;
	if(set_global_arglist(&(cc->timer_arg),
		c->timer_arg)) return -1;
	if(set_global_arglist(&(cc->n_success_arg),
		c->n_success_arg)) return -1;
	if(set_global_arglist(&(cc->n_failure_arg),
		c->n_failure_arg)) return -1;
	if(set_global_arglist(&(cc->keep),
		c->keep)) return -1;
	if(set_global_str(&(cc->dedup_group), c->dedup_group))
		return -1;
	if(set_global_str(&(cc->s_script_pre),
		c->s_script_pre)) return -1;
	if(set_global_arglist(&(cc->s_script_pre_arg),
		c->s_script_pre_arg)) return -1;
	if(set_global_str(&(cc->s_script_post),
		c->s_script_post)) return -1;
	if(set_global_arglist(&(cc->s_script_post_arg),
		c->s_script_post_arg)) return -1;
	if(set_global_str(&(cc->s_script),
		c->s_script)) return -1;
	if(set_global_arglist(&(cc->s_script_arg),
		c->s_script_arg)) return -1;
	if(set_global_arglist(&(cc->rclients),
		c->rclients)) return -1;

	// If ssl_peer_cn is not set, default it to the client name.
	if(!c->ssl_peer_cn
	  && set_global_str(&(cc->ssl_peer_cn), cc->cname))
		return -1;

	return 0;
}

static void conf_init_save_cname_and_version(struct conf *cc)
{
	char *cname=cc->cname;
	char *cversion=cc->peer_version;

	cc->cname=NULL;
	cc->peer_version=NULL;
	conf_init(cc);
	cc->cname=cname;
	cc->peer_version=cversion;
}

int conf_load_client(struct conf *c, struct conf *cc)
{
	char *cpath=NULL;
	conf_init_save_cname_and_version(cc);
	if(!(cpath=prepend_s(c->clientconfdir, cc->cname)))
		return -1;
	if(looks_like_tmp_or_hidden_file(cc->cname))
	{
		logp("client name '%s' is invalid\n", cc->cname);
		free(cpath);
		return -1;
	}
	// Some client settings can be globally set in the server conf and
	// overridden in the client specific conf.
	if(conf_set_client_global(c, cc)
	  || conf_load(cpath, cc, 0))
	{
		free(cpath);
		return -1;
	}
	free(cpath);
	return 0;
}
