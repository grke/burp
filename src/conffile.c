#include "burp.h"
#include "alloc.h"
#include "conf.h"
#include "handy.h"
#include "lock.h"
#include "log.h"
#include "msg.h"
#include "pathcmp.h"
#include "prepend.h"
#include "strlist.h"
#include "src/server/timestamp.h"
#include "client/glob_windows.h"

// This will strip off everything after the last quote. So, configs like this
// should work:
// exclude_regex = "[A-Z]:/pagefile.sys" # swap file (Windows XP, 7, 8)
// Return 1 for quotes removed, -1 for error, 0 for OK.
static int remove_quotes(const char *f, char **v, char quote)
{
	char *dp=NULL;
	char *sp=NULL;
	char *copy=NULL;

	// If it does not start with a quote, leave it alone.
	if(**v!=quote) return 0;

	if(!(copy=strdup_w(*v, __func__)))
		return -1;

	for(dp=*v, sp=copy+1; *sp; sp++)
	{
		if(*sp==quote)
		{
			// Found a matching quote. Stop here.
			*dp='\0';
			for(sp++; *sp && isspace(*sp); sp++) { }
			// Do not complain about trailing comments.
			if(*sp && *sp!='#')
				logp("ignoring trailing characters after quote in config '%s = %s'\n", f, copy);
			return 1;
		}
		else if(*sp=='\\')
		{
			sp++;
			*dp=*sp;
			dp++;
			if(*sp!=quote
			  && *sp!='\\')
				logp("unknown escape sequence '\\%c' in config '%s = %s' - treating it as '%c'\n", *sp, f, copy, *sp);
		}
		else
		{
			*dp=*sp;
			dp++;
		}
	}
	logp("Did not find closing quote in config '%s = %s'\n", f, copy);
	*dp='\0';
	return 1;
}

// Get field and value pair.
int conf_get_pair(char buf[], char **f, char **v)
{
	char *cp=NULL;
	char *eq=NULL;

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

	// Strip white space from before the equals sign.
	for(cp=eq-1; *cp && isspace(*cp); cp--) *cp='\0';
	// Skip white space after the equals sign.
	for(cp=eq+1; *cp && isspace(*cp); cp++) { }
	*v=cp;
	// Strip white space at the end of the line.
	for(cp+=strlen(cp)-1; *cp && isspace(*cp); cp--) { *cp='\0'; }

	// FIX THIS: Make this more sophisticated - it should understand
	// escapes, for example.

	switch(remove_quotes(*f, v, '\''))
	{
		case -1: return -1;
		case 1: break;
		default:
			// If single quotes were not removed, try to remove
			// double quotes.
			if(remove_quotes(*f, v, '\"')<0) return -1;
			break;
	}

	if(!*f || !**f || !*v || !**v) return -1;

	return 0;
}

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

static int pre_post_override(struct conf *c,
	struct conf *pre, struct conf *post)
{
	const char *override=get_string(c);
	if(!override) return 0;
	if(set_string(c, get_string(pre))
	  || set_string(c, get_string(post))
	  || set_string(c, NULL))
		return -1;
	return 0;
}

#ifdef HAVE_LINUX_OS
struct fstype
{
	const char *str;
	uint64_t flag;
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

static int load_conf_field_and_value(struct conf **c,
	const char *f, // field
	const char *v, // value
	const char *conf_path,
	int line)
{
	if(!strcmp(f, "compression"))
	{
		int compression=get_compression(v);
		if(compression<0) return -1;
		set_int(c[OPT_COMPRESSION], compression);
	}
	else if(!strcmp(f, "ssl_compression"))
	{
		int compression=get_compression(v);
		if(compression<0) return -1;
		set_int(c[OPT_SSL_COMPRESSION], compression);
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
		set_float(c[OPT_RATELIMIT], f);
	}
	else
	{
		int i=0;
		for(i=0; i<OPT_MAX; i++)
		{
			if(strcmp(c[i]->field, f)) continue;
			switch(c[i]->conf_type)
			{
				case CT_STRING:
					return set_string(c[i], v);
				case CT_UINT:
					return set_int(c[i], atoi(v));
				case CT_FLOAT:
					return set_float(c[i], atof(v));
					break;
				case CT_MODE_T:
					return set_mode_t(c[i],
						strtol(v, NULL, 8));
				case CT_SSIZE_T:
				{
					ssize_t s=0;
					return
					 get_file_size(v, &s, conf_path, line)
					  || set_ssize_t(c[i], s);
				}
				case CT_E_BURP_MODE:
					return set_e_burp_mode(c[i],
						str_to_burp_mode(v));
				case CT_E_PROTOCOL:
					return set_e_protocol(c[i],
						str_to_protocol(v));
				case CT_E_RECOVERY_METHOD:
					return set_e_recovery_method(c[i],
						str_to_recovery_method(v));
				case CT_STRLIST:
					return add_to_strlist(c[i], v,
					  !strcmp(c[i]->field, "include"));
				case CT_CNTR:
					break;
				// No default so we get a warning if something
				// was missed;
			}
		}
	}
	return 0;
}

// Recursing, so need to define this ahead of conf_parse_line.
static int load_conf_lines_from_file(const char *conf_path,
	struct conf **confs);

static int conf_parse_line(struct conf **confs, const char *conf_path,
	char buf[], int line)
{
	int ret=-1;
	char *f=NULL; // field
	char *v=NULL; // value
	char *copy=NULL;
	char *extrafile=NULL;

	if(!strncmp(buf, ". ", 2))
	{
		// The conf file specifies another file to include.
		char *np=NULL;

		if(!(extrafile=strdup_w(buf+2, __func__))) goto end;

		if((np=strrchr(extrafile, '\n'))) *np='\0';
		if(!*extrafile) goto end;

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
			char *tmp=NULL;
			if(!(copy=strdup_w(conf_path, __func__)))
				goto end;
			if((cp=strrchr(copy, '/'))) *cp='\0';
			if(!(tmp=prepend_s(copy, extrafile)))
			{
				log_out_of_memory(__func__);
				goto end;
			}
			free_w(&extrafile);
			extrafile=tmp;
		}

		ret=load_conf_lines(extrafile, confs);
		goto end;
	}

	if(conf_get_pair(buf, &f, &v)) goto end;
	if(f && v
	  && load_conf_field_and_value(confs, f, v, conf_path, line))
		goto end;
	ret=0;
end:
	free_w(&extrafile);
	free_w(&copy);
	return ret;
}

static void conf_problem(const char *conf_path, const char *msg, int *r)
{
	logp("%s: %s\n", conf_path, msg);
	(*r)--;
}

#ifdef HAVE_IPV6
// These should work for IPv4 connections too.
#define DEFAULT_ADDRESS_MAIN	"::"
#define DEFAULT_ADDRESS_STATUS	"::1"
#else
// Fall back to IPv4 address if IPv6 is not compiled in.
#define DEFAULT_ADDRESS_MAIN	"0.0.0.0"
#define DEFAULT_ADDRESS_STATUS	"127.0.0.1"
#endif

static int server_conf_checks(struct conf **c, const char *path, int *r)
{
	// FIX THIS: Most of this could be done by flags.
	if(!get_string(c[OPT_ADDRESS])
	  && set_string(c[OPT_ADDRESS], DEFAULT_ADDRESS_MAIN))
			return -1;
	if(!get_string(c[OPT_DIRECTORY]))
		conf_problem(path, "directory unset", r);
	if(!get_string(c[OPT_DEDUP_GROUP]))
		conf_problem(path, "dedup_group unset", r);
	if(!get_string(c[OPT_CLIENTCONFDIR]))
		conf_problem(path, "clientconfdir unset", r);
	if(get_e_recovery_method(c[OPT_WORKING_DIR_RECOVERY_METHOD])==RECOVERY_METHOD_UNSET)
		conf_problem(path, "working_dir_recovery_method unset", r);
	if(!get_string(c[OPT_SSL_DHFILE]))
		conf_problem(path, "ssl_dhfile unset", r);
	if(get_string(c[OPT_ENCRYPTION_PASSWORD]))
		conf_problem(path,
		  "encryption_password should not be set on the server!", r);
	if(!get_string(c[OPT_STATUS_ADDRESS])
	  && set_string(c[OPT_STATUS_ADDRESS], DEFAULT_ADDRESS_STATUS))
			return -1;
	if(!get_string(c[OPT_STATUS_PORT])) // carry on if not set.
		logp("%s: status_port unset", path);
	if(!get_int(c[OPT_MAX_CHILDREN]))
		conf_problem(path, "max_children unset", r);
	if(!get_int(c[OPT_MAX_STATUS_CHILDREN]))
		conf_problem(path, "max_status_children unset", r);
	if(!get_strlist(c[OPT_KEEP]))
		conf_problem(path, "keep unset", r);
	if(get_int(c[OPT_MAX_HARDLINKS])<2)
		conf_problem(path, "max_hardlinks too low", r);
	if(get_int(c[OPT_MAX_CHILDREN])<=0)
		conf_problem(path, "max_children too low", r);
	if(get_int(c[OPT_MAX_STATUS_CHILDREN])<=0)
		conf_problem(path, "max_status_children too low", r);
	if(get_int(c[OPT_MAX_STORAGE_SUBDIRS])<=1000)
		conf_problem(path, "max_storage_subdirs too low", r);
	if(!get_string(c[OPT_TIMESTAMP_FORMAT])
	  && set_string(c[OPT_TIMESTAMP_FORMAT], DEFAULT_TIMESTAMP_FORMAT))
			return -1;
	if(get_string(c[OPT_CA_CONF]))
	{
		int ca_err=0;
		if(!get_string(c[OPT_CA_NAME]))
		{
			logp("ca_conf set, but ca_name not set\n");
			ca_err++;
		}
		if(!get_string(c[OPT_CA_SERVER_NAME]))
		{
			logp("ca_conf set, but ca_server_name not set\n");
			ca_err++;
		}
		if(!get_string(c[OPT_CA_BURP_CA]))
		{
			logp("ca_conf set, but ca_burp_ca not set\n");
			ca_err++;
		}
		if(!get_string(c[OPT_SSL_DHFILE]))
		{
			logp("ca_conf set, but ssl_dhfile not set\n");
			ca_err++;
		}
		if(!get_string(c[OPT_SSL_CERT_CA]))
		{
			logp("ca_conf set, but ssl_cert_ca not set\n");
			ca_err++;
		}
		if(!get_string(c[OPT_SSL_CERT]))
		{
			logp("ca_conf set, but ssl_cert not set\n");
			ca_err++;
		}
		if(!get_string(c[OPT_SSL_KEY]))
		{
			logp("ca_conf set, but ssl_key not set\n");
			ca_err++;
		}
		if(ca_err) return -1;
	}
	if(get_string(c[OPT_MANUAL_DELETE]))
	{
		if(path_checks(get_string(c[OPT_MANUAL_DELETE]),
			"ERROR: Please use an absolute manual_delete path.\n"))
				return -1;
	}

	return 0;
}

#ifdef HAVE_WIN32
#undef X509_NAME
#include <openssl/x509.h>
#endif

static char *extract_cn(X509_NAME *subj)
{
	int nid;
	int index;
	ASN1_STRING *d;
	X509_NAME_ENTRY *e;

	nid=OBJ_txt2nid("CN");
	if((index=X509_NAME_get_index_by_NID(subj, nid, -1))<0
	  || !(e=X509_NAME_get_entry(subj, index))
	  || !(d=X509_NAME_ENTRY_get_data(e)))
		return NULL;
	return (char *)ASN1_STRING_data(d);
}

static int get_cname_from_ssl_cert(struct conf **c)
{
	int ret=-1;
	FILE *fp=NULL;
	X509 *cert=NULL;
	X509_NAME *subj=NULL;
	char *path=get_string(c[OPT_SSL_CERT]);
	const char *cn=NULL;

	if(!path || !(fp=open_file(path, "rb"))) return 0;

	if(!(cert=PEM_read_X509(fp, NULL, NULL, NULL)))
	{
		logp("unable to parse %s in: %s\n", path, __func__);
		goto end;
	}
	if(!(subj=X509_get_subject_name(cert)))
	{
		logp("unable to get subject from %s in: %s\n", path, __func__);
		goto end;
	}

	if(!(cn=extract_cn(subj)))
	{
		logp("could not get CN from %s\n", path);
		goto end;
	}
	if(set_string(c[OPT_CNAME], cn))
		goto end;
	logp("cname from cert: %s\n", cn);

	ret=0;
end:
	if(cert) X509_free(cert);
	if(fp) fclose(fp);
	return ret;
}

#ifdef HAVE_WIN32
#include <winsock2.h>
#include <ws2tcpip.h>
#endif

static int get_fqdn(struct conf **c)
{
	int ret=-1;
	int gai_result;
	struct addrinfo hints;
	struct addrinfo *info;
	char hostname[1024]="";
	hostname[1023] = '\0';
	if(gethostname(hostname, 1023))
	{
		logp("gethostname() failed: %s\n", strerror(errno));
		goto end;
	}

	memset(&hints, 0, sizeof hints);
	hints.ai_family=AF_UNSPEC;
	hints.ai_socktype=SOCK_STREAM;
	hints.ai_flags=AI_CANONNAME;

	if((gai_result=getaddrinfo(hostname, "http", &hints, &info)))
	{
		logp("getaddrinfo in %s: %s\n", __func__,
			gai_strerror(gai_result));
		goto end;
	}

	//for(p=info; p; p=p->ai_next)
	// Just use the first one.
	if(!info)
	{
		logp("Got no hostname in %s\n", __func__);
		goto end;
	}

	if(set_string(c[OPT_CNAME], info->ai_canonname))
		goto end;
	logp("cname from hostname: %s\n", get_string(c[OPT_CNAME]));

	ret=0;
end:
	freeaddrinfo(info);
	return ret;
}

const char *confs_get_lockfile(struct conf **confs)
{
	const char *lockfile=get_string(confs[OPT_LOCKFILE]);
	if(!lockfile) lockfile=get_string(confs[OPT_PIDFILE]);
	return lockfile;
}

static int general_conf_checks(struct conf **c, const char *path, int *r)
{
	if(!confs_get_lockfile(c))
		conf_problem(path, "lockfile unset", r);
	if(!get_string(c[OPT_SSL_CERT]))
		conf_problem(path, "ssl_cert unset", r);
	if(!get_string(c[OPT_SSL_CERT_CA]))
		conf_problem(path, "ssl_cert_ca unset", r);
	return 0;
}

static int client_conf_checks(struct conf **c, const char *path, int *r)
{
	const char *autoupgrade_os=get_string(c[OPT_AUTOUPGRADE_OS]);
	if(!get_string(c[OPT_CNAME]))
	{
		if(get_cname_from_ssl_cert(c)) return -1;
		// There was no error. This is probably a new install.
		// Try getting the fqdn and using that.
		if(!get_string(c[OPT_CNAME]))
		{
			if(get_fqdn(c)) return -1;
			if(!get_string(c[OPT_CNAME]))
				conf_problem(path, "client name unset", r);
		}
	}
	if(!get_string(c[OPT_PASSWORD]))
	{
		logp("password not set, falling back to \"password\"\n");
		if(set_string(c[OPT_PASSWORD], "password"))
			return -1;
	}
	if(!get_string(c[OPT_SERVER]))
		conf_problem(path, "server unset", r);
	if(!get_string(c[OPT_STATUS_PORT])) // carry on if not set.
		logp("%s: status_port unset\n", path);
	if(!get_string(c[OPT_SSL_PEER_CN]))
	{
		const char *server=get_string(c[OPT_SERVER]);
		logp("ssl_peer_cn unset\n");
		if(!server)
		{
			logp("falling back to '%s'\n", server);
			if(set_string(c[OPT_SSL_PEER_CN], server))
				return -1;
		}
	}
	if(autoupgrade_os
	  && strstr(autoupgrade_os, ".."))
		conf_problem(path,
			"autoupgrade_os must not contain a '..' component", r);
	if(!get_string(c[OPT_CA_BURP_CA]))
	{
		if(!get_string(c[OPT_CA_CSR_DIR]))
			conf_problem(path,
				"ca_burp_ca set, but ca_csr_dir not set\n", r);
		if(!get_string(c[OPT_SSL_CERT_CA]))
			conf_problem(path,
				"ca_burp_ca set, but ssl_cert_ca not set\n", r);
		if(!get_string(c[OPT_SSL_CERT]))
			conf_problem(path,
				"ca_burp_ca set, but ssl_cert not set\n", r);
		if(!get_string(c[OPT_SSL_KEY]))
			conf_problem(path,
				"ca_burp_ca set, but ssl_key not set\n", r);
	}

	if(!r)
	{
		struct strlist *l;
		logp("Listing configured paths:\n");
		for(l=get_strlist(c[OPT_INCEXCDIR]); l; l=l->next)
			logp("%s: %s\n", l->flag?"include":"exclude", l->path);
		logp("Listing starting paths:\n");
		for(l=get_strlist(c[OPT_STARTDIR]); l; l=l->next)
			if(l->flag) logp("%s\n", l->path);
	}
	return 0;
}

static int finalise_keep_args(struct conf **c)
{
	struct strlist *k;
	struct strlist *last=NULL;
	unsigned long long mult=1;
	for(k=get_strlist(c[OPT_KEEP]); k; k=k->next)
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
	k=get_strlist(c[OPT_KEEP]);
	if(k && k->next) last->flag++;
	return 0;
}

static int incexc_munge(struct conf **c, struct strlist *s)
{
#ifdef HAVE_WIN32
	convert_backslashes(&s->path);
#endif
	if(path_checks(s->path,
		"ERROR: Please use absolute include/exclude paths.\n"))
			return -1;
	if(add_to_strlist(c[OPT_INCEXCDIR], s->path, s->flag))
		return -1;
	return 0;
}

static int finalise_incexc_dirs(struct conf **c)
{
	struct strlist *s=NULL;

	for(s=get_strlist(c[OPT_INCLUDE]); s; s=s->next)
		if(incexc_munge(c, s)) return -1;
	for(s=get_strlist(c[OPT_EXCLUDE]); s; s=s->next)
		if(incexc_munge(c, s)) return -1;
	return 0;
}

// This decides which directories to start backing up, and which
// are subdirectories which don't need to be started separately.
static int finalise_start_dirs(struct conf **c)
{
	struct strlist *s=NULL;
	struct strlist *last_ie=NULL;
	struct strlist *last_sd=NULL;

	for(s=get_strlist(c[OPT_INCLUDE]); s; s=s->next)
	{
#ifdef HAVE_WIN32
		convert_backslashes(&s->path);
#endif
		if(path_checks(s->path,
			"ERROR: Please use absolute include/exclude paths.\n"))
				return -1;

		// Ensure that we do not backup the same directory twice.
		if(last_ie && !strcmp(s->path, last_ie->path))
		{
			logp("Directory appears twice in conf: %s\n",
				s->path);
			return -1;
		}
		// If it is not a subdirectory of the most recent start point,
		// we have found another start point.
		if(!get_strlist(c[OPT_STARTDIR])
		  || !last_sd || !is_subdir(last_sd->path, s->path))
		{
			// Do not use strlist_add_sorted, because last_sd is
			// relying on incexcdir already being sorted.
			if(add_to_strlist(c[OPT_STARTDIR], s->path, s->flag))
				return -1;
			last_sd=s;
		}
		last_ie=s;
	}
	return 0;
}

// The glob stuff should only run on the client side.
static int finalise_glob(struct conf **c)
{
	int ret=-1;
#ifdef HAVE_WIN32
	if(glob_windows(c)) goto end;
#else
	int i;
	glob_t globbuf;
	struct strlist *l;
	struct strlist *last=NULL;
	memset(&globbuf, 0, sizeof(globbuf));
	for(l=get_strlist(c[OPT_INCGLOB]); l; l=l->next)
	{
		glob(l->path, last?GLOB_APPEND:0, NULL, &globbuf);
		last=l;
	}

	for(i=0; (unsigned int)i<globbuf.gl_pathc; i++)
		if(add_to_strlist_include(c[OPT_INCLUDE], globbuf.gl_pathv[i]))
			goto end;

	globfree(&globbuf);
#endif
	ret=0;
end:
	return ret;
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

static int finalise_fstypes(struct conf **c)
{
	struct strlist *l;
	// Set the strlist flag for the excluded fstypes
	for(l=get_strlist(c[OPT_EXCFS]); l; l=l->next)
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

/*
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
*/

static int conf_finalise(const char *conf_path, struct conf **c)
{
	int s_script_notify=0;
	if(finalise_fstypes(c)) return -1;

	strlist_compile_regexes(get_strlist(c[OPT_INCREG]));
	strlist_compile_regexes(get_strlist(c[OPT_EXCREG]));

	set_max_ext(get_strlist(c[OPT_INCEXT]));
	set_max_ext(get_strlist(c[OPT_EXCEXT]));
	set_max_ext(get_strlist(c[OPT_EXCOM]));

	if(get_e_burp_mode(c[OPT_BURP_MODE])==BURP_MODE_CLIENT
	  && finalise_glob(c)) return -1;

	if(finalise_incexc_dirs(c)
	  || finalise_start_dirs(c))
		return -1;

	if(finalise_keep_args(c)) return -1;

	if(pre_post_override(c[OPT_B_SCRIPT],
		c[OPT_B_SCRIPT_PRE], c[OPT_B_SCRIPT_POST])
	  || pre_post_override(c[OPT_R_SCRIPT],
		c[OPT_R_SCRIPT_PRE], c[OPT_R_SCRIPT_POST])
	  || pre_post_override(c[OPT_S_SCRIPT],
		c[OPT_S_SCRIPT_PRE], c[OPT_S_SCRIPT_POST]))
			return -1;
	if((s_script_notify=get_int(c[OPT_S_SCRIPT_NOTIFY])))
	{
		set_int(c[OPT_S_SCRIPT_PRE_NOTIFY], s_script_notify);
		set_int(c[OPT_S_SCRIPT_POST_NOTIFY], s_script_notify);
	}

/* FIX THIS: Need to figure out what this was supposed to do, and make sure
   burp-2 does it too.
	setup_script_arg_override(l->bslist, conf->bscount,
		&(l->bprelist), &(l->bpostlist),
		&(conf->bprecount), &(conf->bpostcount));
	setup_script_arg_override(l->rslist, conf->rscount,
		&(l->rprelist), &(l->rpostlist),
		&(conf->rprecount), &(conf->rpostcount));
	setup_script_arg_override(conf->server_script_arg, conf->sscount,
		&(l->sprelist), &(l->spostlist),
		&(conf->sprecount), &(conf->spostcount));
*/
	return 0;
}

static int conf_finalise_global_only(const char *conf_path, struct conf **confs)
{
	int r=0;

	if(!get_string(confs[OPT_PORT]))
		conf_problem(conf_path, "port unset", &r);

	// Let the caller check the 'keep' value.

	if(!get_string(confs[OPT_SSL_KEY_PASSWORD])
	  && set_string(confs[OPT_SSL_KEY_PASSWORD], ""))
		r--;

	if(general_conf_checks(confs, conf_path, &r)) r--;

	switch(get_e_burp_mode(confs[OPT_BURP_MODE]))
	{
		case BURP_MODE_SERVER:
			if(server_conf_checks(confs, conf_path, &r)) r--;
			break;
		case BURP_MODE_CLIENT:
			if(client_conf_checks(confs, conf_path, &r)) r--;
			break;
		case BURP_MODE_UNSET:
		default:
			logp("%s: mode unset - need 'server' or 'client'\n",
				conf_path);
			r--;
			break;
	}

	return r;
}

static int load_conf_lines_from_file(const char *conf_path, struct conf **confs)
{
	int ret=0;
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
		if(conf_parse_line(confs, conf_path, buf, line))
		{
			conf_error(conf_path, line);
			ret=-1;
		}
	}
	if(fp) fclose(fp);
	return ret;
}

/* The client runs this when the server overrides the incexcs. */
int conf_parse_incexcs_buf(struct conf **c, const char *incexc)
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
		free_w(&copy);
		return -1;
	}
	do
	{
		line++;
		if(conf_parse_line(c, "", tok, line))
		{
			ret=-1;
			break;
		}
	} while((tok=strtok(NULL, "\n")));
	free_w(&copy);

	if(ret) return ret;
	return conf_finalise("server override", c);
}

/* The server runs this when parsing a restore file on the server. */
int conf_parse_incexcs_path(struct conf **c, const char *path)
{
	free_incexcs(c);
	if(load_conf_lines_from_file(path, c)
	  || conf_finalise(path, c))
		return -1;
	return 0;
}

static int set_global_arglist(struct conf *dst, struct conf *src)
{
	struct strlist *s;
	for(s=get_strlist(src); s; s=s->next)
		if(add_to_strlist(dst, s->path, s->flag))
			return -1;
	return 0;
}

// Remember to update the list in the man page when you change these.
static int conf_set_from_global(struct conf **globalc, struct conf **cc)
{
	int i=0;
	for(i=0; i<OPT_MAX; i++)
	{
		if(!(cc[i]->flags & CONF_FLAG_CC_OVERRIDE))
			continue;
		switch(cc[i]->conf_type)
		{
			case CT_STRING:
				set_string(cc[i], get_string(globalc[i]));
				break;
			case CT_UINT:
				set_int(cc[i], get_int(globalc[i]));
				break;
			case CT_FLOAT:
				set_float(cc[i], get_float(globalc[i]));
				break;
			case CT_MODE_T:
				set_mode_t(cc[i], get_mode_t(globalc[i]));
				break;
			case CT_SSIZE_T:
				set_ssize_t(cc[i], get_ssize_t(globalc[i]));
				break;
			case CT_E_BURP_MODE:
				set_e_burp_mode(cc[i], get_e_burp_mode(globalc[i]));
				break;
			case CT_E_PROTOCOL:
				set_e_protocol(cc[i], get_e_protocol(globalc[i]));
				break;
			case CT_E_RECOVERY_METHOD:
				set_e_recovery_method(cc[i], get_e_recovery_method(globalc[i]));
				break;
			case CT_STRLIST:
				if(set_global_arglist(cc[i], globalc[i]))
					return -1;
				break;
			case CT_CNTR:
				break;
			// No default so that there are warnings if anything
			// was missed.
		}
	}

	// If ssl_peer_cn is not set, default it to the client name.
	if(!get_string(globalc[OPT_SSL_PEER_CN])
	  && set_string(cc[OPT_SSL_PEER_CN], get_string(cc[OPT_CNAME])))
		return -1;

	return 0;
}

// Remember to update the list in the man page when you change these.
// Instead of adding onto the end of the list, these replace the list.
static int conf_set_from_global_arg_list_overrides(struct conf **globalc,
	struct conf **cc)
{
	int i=0;
	for(i=0; i<OPT_MAX; i++)
	{
		if(cc[i]->conf_type!=CT_STRLIST) continue;
		if(!(cc[i]->flags & CONF_FLAG_STRLIST_REPLACE)) continue;
		if(get_strlist(cc[i])) continue; // Was overriden by the client.
		if(set_global_arglist(cc[i], globalc[i])) return -1;
	}
	return 0;
}

static int conf_init_save_cname_and_version(struct conf **cconfs)
{
	int ret=-1;
	char *cname=NULL;
	char *cversion=NULL;

	if(!(cname=strdup_w(get_string(cconfs[OPT_CNAME]), __func__))
	  || !(cversion=
	  strdup_w(get_string(cconfs[OPT_PEER_VERSION]), __func__)))
		goto end;

	set_string(cconfs[OPT_CNAME], NULL);
	set_string(cconfs[OPT_PEER_VERSION], NULL);
	if(confs_init(cconfs)) goto end;
	set_string(cconfs[OPT_CNAME], cname);
	set_string(cconfs[OPT_PEER_VERSION], cversion);
	ret=0;
end:
	free_w(&cname);
	free_w(&cversion);
	return ret;
}

static int conf_load_overrides(struct conf **globalcs, struct conf **cconfs,
	const char *path)
{
	// Some client settings can be globally set in the server conf and
	// overridden in the client specific conf.
	if(conf_set_from_global(globalcs, cconfs)
	  || load_conf_lines_from_file(path, cconfs)
	  || conf_set_from_global_arg_list_overrides(globalcs, cconfs)
	  || conf_finalise(path, cconfs))
		return -1;
	return 0;
}

int conf_load_clientconfdir(struct conf **globalcs, struct conf **cconfs)
{
	int ret=-1;
	char *path=NULL;
	const char *cname=NULL;

	if(conf_init_save_cname_and_version(cconfs)) goto end;
	cname=get_string(cconfs[OPT_CNAME]);
	if(looks_like_tmp_or_hidden_file(cname))
	{
		logp("client name '%s' is invalid\n", cname);
		goto end;
	}

	if(!(path=prepend_s(get_string(globalcs[OPT_CLIENTCONFDIR]), cname)))
		goto end;
	ret=conf_load_overrides(globalcs, cconfs, path);
end:
	free_w(&path);
	return ret;
}

int conf_load_global_only(const char *path, struct conf **globalcs)
{
	if(set_string(globalcs[OPT_CONFFILE], path)
	  || load_conf_lines_from_file(path, globalcs)
	  || conf_finalise(path, globalcs)
	  || conf_finalise_global_only(path, globalcs))
		return -1;
	return 0;
}
