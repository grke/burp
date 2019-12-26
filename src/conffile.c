#include "burp.h"
#include "alloc.h"
#include "conf.h"
#include "fsops.h"
#include "handy.h"
#include "lock.h"
#include "log.h"
#include "msg.h"
#include "pathcmp.h"
#include "prepend.h"
#include "strlist.h"
#include "times.h"
#include "client/glob_windows.h"
#include "conffile.h"

static struct strlist *cli_overrides=NULL;

void conf_set_cli_overrides(struct strlist *overrides)
{
	cli_overrides=overrides;
}

// This will strip off everything after the last quote. So, configs like this
// should work:
// exclude_regex = "[A-Z]:/pagefile.sys" # swap file (Windows XP, 7, 8)
// Return 1 for quotes removed, -1 for error, 0 for OK.
static int remove_quotes(const char *f, char **v, char quote)
{
	char *dp=NULL;
	char *sp=NULL;
	char *copy=NULL;
	int ret=1;

	// If it does not start with a quote, leave it alone.
	if(**v!=quote) return 0;

	if(!(copy=strdup_w(*v, __func__)))
	{
		ret=-1;
		goto end;
	}

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
			goto end;
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
end:
	free_w(&copy);
	return ret;
}

// Get field and value pair.
int conf_get_pair(char buf[], char **f, char **v, int *r)
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
	for(cp=eq-1; *cp && (isspace(*cp) || *cp == ':'); cp--)
	{
		if(*cp == ':') *r=1;
		*cp='\0';
	}
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

static int conf_error(const char *conf_path, int line)
{
	logp("%s: parse error on line %d\n", conf_path, line);
	return -1;
}

int get_file_size(const char *v, uint64_t *dest, const char *conf_path, int line)
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
	if(set_string(pre, override)
	  || set_string(post, override))
		return -1;
	return 0;
}

#ifdef HAVE_LINUX_OS
struct fstype
{
	const char *str;
	uint64_t flag;
};

// Sorted in magic number order.
static struct fstype fstypes[]={
	{ "devfs",		0x00001373 },
	{ "devpts",		0x00001CD1 },
	{ "smbfs",		0x0000517B },
	{ "nfs",		0x00006969 },
	{ "romfs",		0x00007275 },
	{ "iso9660",		0x00009660 },
	{ "devtmpfs",		0x00009FA0 },
	{ "proc",		0x00009FA0 },
	{ "usbdevfs",		0x00009FA2 },
	{ "ext2",		0x0000EF53 },
	{ "ext3",		0x0000EF53 },
	{ "ext4",		0x0000EF53 },
	{ "ecryptfs",		0x0000F15F },
	{ "cgroup",		0x0027E0EB },
	{ "ceph",		0x00C36400 },
	{ "tmpfs",		0x01021994 },
	{ "zfs",		0x2FC12FC1 },
	{ "jfs",		0x3153464A },
	{ "autofs",		0x42494E4D },
	{ "reiserfs",		0x52654973 },
	{ "ntfs",		0x5346544E },
	{ "xfs",		0x58465342 },
	{ "sysfs",		0x62656572 },
	{ "debugfs",		0x64626720 },
	{ "fusectl", 		0x65735543 },
	{ "fuse.lxcfs",		0x65735546 },
	{ "securityfs",		0x73636673 },
	{ "ramfs",		0x858458F6 },
	{ "btrfs",		0x9123683E },
	{ "hugetlbfs",		0x958458F6 },
	{ "smb2",		0xFE534D42 },
	{ "cifs",		0xFF534D42 },
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
	int reset, // reset flag
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
					uint64_t s=0;
					return
					 get_file_size(v, &s, conf_path, line)
					  || set_uint64_t(c[i], s);
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
					if (reset) set_strlist(c[i], 0);
					return add_to_strlist(c[i], v,
					  !strcmp(c[i]->field, "include"));
				case CT_E_RSHASH:
					break;
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
static int conf_load_lines_from_file(const char *conf_path,
	struct conf **confs);

static int deal_with_dot_inclusion(const char *conf_path,
	char **extrafile, struct conf **confs)
{
	int ret=-1;
	char *copy=NULL;
#ifndef HAVE_WIN32
	int i=0;
	glob_t globbuf;
	if(**extrafile!='/')
#else
	if(strlen(*extrafile)>2
	  && (*extrafile)[1]!=':')
#endif
	{
		// It is relative to the directory that the
		// current conf file is in.
		char *cp=NULL;
		char *tmp=NULL;
		if(!(copy=strdup_w(conf_path, __func__)))
			goto end;
		if((cp=strrchr(copy, '/'))) *cp='\0';
		if(!(tmp=prepend_s(copy, *extrafile)))
		{
			log_out_of_memory(__func__);
			goto end;
		}
		free_w(extrafile);
		*extrafile=tmp;
	}
#ifndef HAVE_WIN32
	// Treat it is a glob expression.
	memset(&globbuf, 0, sizeof(globbuf));
	glob(*extrafile, 0, NULL, &globbuf);
	for(i=0; (unsigned int)i<globbuf.gl_pathc; i++)
		if((ret=conf_load_lines_from_file(globbuf.gl_pathv[i], confs)))
			goto end;

	globfree(&globbuf);
#else
	ret=conf_load_lines_from_file(*extrafile, confs);
#endif

end:
	free_w(&copy);
	return ret;
}

static int conf_parse_line(struct conf **confs, const char *conf_path,
	char buf[], int line)
{
	int ret=-1;
	int r=0;
	char *f=NULL; // field
	char *v=NULL; // value
	char *extrafile=NULL;

	if(!strncmp(buf, ". ", 2))
	{
		// The conf file specifies another file to include.
		char *np=NULL;

		if(!(extrafile=strdup_w(buf+2, __func__))) goto end;

		if((np=strrchr(extrafile, '\n'))) *np='\0';
		if(!*extrafile) goto end;

		ret=deal_with_dot_inclusion(conf_path, &extrafile, confs);
		goto end;
	}

	if(conf_get_pair(buf, &f, &v, &r)) goto end;
	if(f && v
	  && load_conf_field_and_value(confs, f, v, r, conf_path, line))
		goto end;
	ret=0;
end:
	free_w(&extrafile);
	return ret;
}

static void conf_problem(const char *conf_path, const char *msg, int *r)
{
	logp("%s: %s\n", conf_path, msg);
	(*r)--;
}

static void burp_ca_conf_problem(const char *conf_path,
	const char *field, int *r)
{
	char msg[128]="";
	snprintf(msg, sizeof(msg), "ca_%s_ca set, but %s not set\n",
		PACKAGE_TARNAME, field);
	conf_problem(conf_path, msg, r);
}

static int server_conf_checks(struct conf **c, const char *path, int *r)
{
	// FIX THIS: Most of this could be done by flags.
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
	if(!get_strlist(c[OPT_KEEP]))
		conf_problem(path, "keep unset", r);
	if(get_int(c[OPT_MAX_HARDLINKS])<2)
		conf_problem(path, "max_hardlinks too low", r);

	if(get_int(c[OPT_MAX_STORAGE_SUBDIRS])<=1000)
		conf_problem(path, "max_storage_subdirs too low", r);
	if(!get_string(c[OPT_TIMESTAMP_FORMAT])
	  && set_string(c[OPT_TIMESTAMP_FORMAT], DEFAULT_TIMESTAMP_FORMAT))
			return -1;
	if(get_string(c[OPT_CA_CONF]))
	{
		int ca_err=0;
		const char *ca_name=get_string(c[OPT_CA_NAME]);
		const char *ca_server_name=get_string(c[OPT_CA_SERVER_NAME]);
		if(!ca_name)
		{
			logp("ca_conf set, but ca_name not set\n");
			ca_err++;
		}
		if(!ca_server_name)
		{
			logp("ca_conf set, but ca_server_name not set\n");
			ca_err++;
		}
		if(ca_name
		  && ca_server_name
		  && !strcmp(ca_name, ca_server_name))
		{
			logp("ca_name and ca_server_name cannot be the same\n");
			ca_err++;
		}
		if(!get_string(c[OPT_CA_BURP_CA]))
		{
			logp("ca_conf set, but ca_%s_ca not set\n",
				PACKAGE_TARNAME);
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
		if(!is_absolute(get_string(c[OPT_MANUAL_DELETE])))
		{
			logp("ERROR: Please use an absolute manual_delete path.\n");
			return -1;
		}
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
#if OPENSSL_VERSION_NUMBER < 0x1010000fL || defined(LIBRESSL_VERSION_NUMBER)
		return (char *)ASN1_STRING_data(d);
#else
		return (char *)ASN1_STRING_get0_data(d);
#endif
}

static void mangle_cname(char **cname, struct conf **c)
{
	if(!get_int(c[OPT_CNAME_FQDN]))
		strip_fqdn(cname);
	if(get_int(c[OPT_CNAME_LOWERCASE]))
		strlwr(*cname);
}

static int get_cname_from_ssl_cert(struct conf **c)
{
	int ret=-1;
	struct fzp *fzp=NULL;
	X509 *cert=NULL;
	X509_NAME *subj=NULL;
	char *path=get_string(c[OPT_SSL_CERT]);
	const char *cn=NULL;
	char *copy=NULL;

	if(!path || !(fzp=fzp_open(path, "rb"))) return 0;

	if(!(cert=fzp_PEM_read_X509(fzp)))
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
	if(!(copy=strdup_w(cn, __func__)))
		goto end;
	mangle_cname(&copy, c);
	if(set_string(c[OPT_CNAME], copy))
		goto end;
	logp("cname from cert: %s\n", cn);
	if(strcmp(copy, cn))
		logp("cname mangled to: %s\n", copy);

	ret=0;
end:
	if(cert) X509_free(cert);
	fzp_close(&fzp);
	free_w(&copy);
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
	struct addrinfo *info=NULL;
	char hostname[1024]="";
	char *fqdn=NULL;
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

	if((gai_result=getaddrinfo(hostname, NULL, &hints, &info)))
	{
		logp("getaddrinfo in %s: %s\n", __func__,
			gai_strerror(gai_result));
		logp("Using %s\n", hostname);
		if(!(fqdn=strdup_w(hostname, __func__)))
			goto end;
	}
	else
	{
		//for(p=info; p; p=p->ai_next)
		// Just use the first one.
		if(!info)
		{
			logp("Got no hostname in %s\n", __func__);
			goto end;
		}
		if(!(fqdn=strdup_w(info->ai_canonname, __func__)))
			goto end;
	}

	mangle_cname(&fqdn, c);

	if(set_string(c[OPT_CNAME], fqdn))
		goto end;
	logp("cname from hostname: %s\n", get_string(c[OPT_CNAME]));

	ret=0;
end:
	if(info) freeaddrinfo(info);
	free_w(&fqdn);
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
	int ret=-1;
	char *copy=NULL;
	const char *autoupgrade_os=get_string(c[OPT_AUTOUPGRADE_OS]);

	if(!get_string(c[OPT_CNAME]))
	{
		if(get_cname_from_ssl_cert(c))
			goto end;
		// There was no error. This is probably a new install.
		// Try getting the fqdn and using that.
		if(!get_string(c[OPT_CNAME]))
		{
			if(get_fqdn(c))
				goto end;
			if(!get_string(c[OPT_CNAME]))
				conf_problem(path, "client name unset", r);
		}
	}
	if(!get_string(c[OPT_PASSWORD]))
	{
		logp("password not set, falling back to \"password\"\n");
		if(set_string(c[OPT_PASSWORD], "password"))
			goto end;
	}
	if(!get_string(c[OPT_SERVER]))
		conf_problem(path, "server unset", r);
	if(!get_string(c[OPT_SSL_PEER_CN]))
	{
		const char *server=get_string(c[OPT_SERVER]);
		logp("ssl_peer_cn unset\n");
		if(server)
		{
			char *cp=NULL;
			if(!(copy=strdup_w(server, __func__)))
				goto end;
			
			if((cp=strchr(copy, ':')))
				*cp='\0';
			logp("falling back to '%s'\n", copy);
			if(set_string(c[OPT_SSL_PEER_CN], copy))
				goto end;
		}
	}
	if(autoupgrade_os
	  && strstr(autoupgrade_os, ".."))
		conf_problem(path,
			"autoupgrade_os must not contain a '..' component", r);
	if(get_string(c[OPT_CA_BURP_CA]))
	{
		if(!get_string(c[OPT_CA_CSR_DIR]))
			burp_ca_conf_problem(path, "ca_csr_dir", r);
		if(!get_string(c[OPT_SSL_CERT_CA]))
			burp_ca_conf_problem(path, "ssl_cert_ca", r);
		if(!get_string(c[OPT_SSL_CERT]))
			burp_ca_conf_problem(path, "ssl_cert", r);
		if(!get_string(c[OPT_SSL_KEY]))
			burp_ca_conf_problem(path, "ssl_key", r);
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

	ret=0;
end:
	free_w(&copy);
	return ret;
}

static int finalise_keep_args(struct conf **c)
{
	struct strlist *k;
	struct strlist *last=NULL;
	uint64_t mult=1;
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
	if(!is_absolute(s->path))
	{
		logp("ERROR: Please use absolute include/exclude paths.\n");
		return -1;
	}
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
	if(get_strlist(c[OPT_INCREG]) &&
	   !(get_strlist(c[OPT_INCLUDE]) || get_strlist(c[OPT_INCGLOB])))
	{
		logp("Need at least one 'include' or 'include_glob' for the 'include_regex' to work.\n");
		return -1;
	}
	return 0;
}

static int add_to_cross_filesystem(struct conf **c, const char *path)
{
	if(strlist_find(get_strlist(c[OPT_FSCHGDIR]), path, 0))
		return 0;
	return add_to_strlist(c[OPT_FSCHGDIR], path, 0);
}

static int check_start_dirs_and_seed(struct conf **c)
{
	int errors=0;
	struct strlist *s=NULL;
	const char *src=get_string(c[OPT_SEED_SRC]);
	if(!src)
		return 0;

	for(s=get_strlist(c[OPT_STARTDIR]); s; s=s->next)
	{
		if(!is_subdir(src, s->path))
		{
			logp("ERROR: Starting directories need to be within %s:%s: %s\n",
				c[OPT_SEED_SRC]->field, src, s->path);
			errors++;
		}
	}

	return errors;
}

// This decides which directories to start backing up, and which
// are subdirectories which don't need to be started separately.
static int finalise_start_dirs(struct conf **c)
{
	struct strlist *s=NULL;
	struct strlist *last_ie=NULL;
	struct strlist *last_sd=NULL;

	// Make sure that the startdir list starts empty, or chaos will ensue.
	conf_free_content(c[OPT_STARTDIR]);

	for(s=get_strlist(c[OPT_INCLUDE]); s; s=s->next)
	{
#ifdef HAVE_WIN32
		convert_backslashes(&s->path);
#endif
		if(!is_absolute(s->path))
		{
			logp("ERROR: Please use absolute include/exclude paths.\n");
			return -1;
		}

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
		else
		{
			// If it is not a starting directory, it should at
			// least be included as a cross_filesystem entry.
			if(add_to_cross_filesystem(c, s->path))
				return -1;
		}
		last_ie=s;
	}

	if(check_start_dirs_and_seed(c))
		return -1;

	return 0;
}

static int finalise_fschg_dirs(struct conf **c)
{
	struct strlist *s;
	for(s=get_strlist(c[OPT_FSCHGDIR]); s; s=s->next)
		strip_trailing_slashes(&s->path);
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
		if(add_to_strlist_include_uniq(c[OPT_INCLUDE], globbuf.gl_pathv[i]))
			goto end;

	globfree(&globbuf);
#endif
	ret=0;
end:
	return ret;
}

// Reeval the glob after script pre
int reeval_glob(struct conf **c)
{
	if(finalise_glob(c))
		return -1;

	if(finalise_incexc_dirs(c)
	  || finalise_start_dirs(c)
	  || finalise_fschg_dirs(c))
		return -1;

	return 0;
}

// Set the flag of the first item in a list that looks at extensions to the
// maximum number of characters that need to be checked, plus one. This is for
// a bit of added efficiency.
static void set_max_ext(struct strlist *list)
{
	int max=0;
	struct strlist *l=NULL;
	for(l=list; l; l=l->next)
	{
		int s=strlen(l->path);
		if(s>max) max=s;
	}
	if(list) list->flag=max+1;
}

static int finalise_fstypes(struct conf **c, int opt)
{
	struct strlist *l;
	// Set the strlist flag for the excluded fstypes
	for(l=get_strlist(c[opt]); l; l=l->next)
	{
		l->flag=0;
		if(!strncasecmp(l->path, "0x", 2))
		{
			l->flag=strtol((l->path)+2, NULL, 16);
			logp("Excluding file system type 0x%08lX\n", l->flag);
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

static int setup_script_arg_override(struct conf *c, struct conf *args)
{
	struct strlist *s;
	set_strlist(args, NULL);
	for(s=get_strlist(c); s; s=s->next)
		if(add_to_strlist(args, s->path, s->flag))
			return -1;
	return 0;
}

static int setup_script_arg_overrides(struct conf *c,
	struct conf *pre_args, struct conf *post_args)
{
	if(!get_strlist(c)) return 0;
	return setup_script_arg_override(c, pre_args)
	  || setup_script_arg_override(c, post_args);
}

static int listen_config_ok(const char *l)
{
	int port;
	const char *c=NULL;
	const char *cp=NULL;

	for(c=l; *c; c++)
		if(!isalnum(*c) && *c!=':' && *c!='.')
			return 0;

	if(!(cp=strrchr(l, ':')))
		return 0;
	if(l==cp)
		return 0;
	cp++;
	if(!strlen(cp) || strlen(cp)>5)
		return 0;
	port=atoi(cp);
	if(port<=0 || port>65535)
		return 0;

	return 1;
}

static int finalise_server_max_children(struct conf **c,
	enum conf_opt listen_opt, enum conf_opt max_children_opt)
{
	struct strlist *l;
	struct strlist *mc;
	long max_children=5;

	for(l=get_strlist(c[listen_opt]),
	   mc=get_strlist(c[max_children_opt]); l; l=l->next)
	{
		if(!listen_config_ok(l->path))
		{
			logp("Could not parse %s config '%s'\n",
				c[listen_opt]->field, l->path);
			return -1;
		}
		if(mc)
		{
			if((max_children=atol(mc->path))<=0)
			{
				logp("%s too low for %s %s\n",
					c[max_children_opt]->field,
					c[listen_opt]->field,
					l->path);
				return -1;
			}
			l->flag=max_children;

			mc=mc->next;
		}
		else
		{
			logp("%s %s defaulting to %s %lu\n",
				c[listen_opt]->field,
				l->path,
				c[max_children_opt]->field,
				max_children);
			l->flag=max_children;
		}
	}

	if(mc)
	{
		logp("too many %s options\n", c[max_children_opt]->field);
		return -1;
	}

	return 0;
}

static int finalise_client_ports(struct conf **c)
{
	int port=0;
	struct strlist *p;

	for(p=get_strlist(c[OPT_PORT]); p; p=p->next)
		port=atoi(p->path);

	if(!port)
		return 0;

	if(!get_int(c[OPT_PORT_BACKUP]))
		set_int(c[OPT_PORT_BACKUP], port);
	if(!get_int(c[OPT_PORT_RESTORE]))
		set_int(c[OPT_PORT_RESTORE], port);
	if(!get_int(c[OPT_PORT_VERIFY]))
		set_int(c[OPT_PORT_VERIFY], get_int(c[OPT_PORT_RESTORE]));
	if(!get_int(c[OPT_PORT_LIST]))
		set_int(c[OPT_PORT_LIST], port);
	if(!get_int(c[OPT_PORT_DELETE]))
		set_int(c[OPT_PORT_DELETE], port);

	return 0;
}

static int apply_cli_overrides(struct conf **confs)
{
	int ret=-1;
	int line=0;
	char *opt=NULL;
	struct strlist *oo=NULL;

	for(oo=cli_overrides; oo; oo=oo->next)
	{
		line++;
		free_w(&opt);
		if(!(opt=strdup_w(oo->path, __func__)))
			goto end;
		if((ret=conf_parse_line(confs, "", opt, line)))
		{
			logp("Unable to parse cli option %d '%s'\n",
				line, oo->path);
			goto end;
		}
	}
	ret=0;
end:
	free_w(&opt);
	return ret;
}

static int conf_finalise(struct conf **c)
{
	enum burp_mode burp_mode;
	int s_script_notify=0;

	if(apply_cli_overrides(c))
		return -1;

	burp_mode=get_e_burp_mode(c[OPT_BURP_MODE]);

	if(finalise_fstypes(c, OPT_EXCFS)
	  || finalise_fstypes(c, OPT_INCFS))
		return -1;

	strlist_compile_regexes(get_strlist(c[OPT_INCREG]));
	strlist_compile_regexes(get_strlist(c[OPT_EXCREG]));

	set_max_ext(get_strlist(c[OPT_INCEXT]));
	set_max_ext(get_strlist(c[OPT_EXCEXT]));
	set_max_ext(get_strlist(c[OPT_EXCOM]));

	if(burp_mode==BURP_MODE_CLIENT
	  && finalise_glob(c))
		return -1;

	if(finalise_incexc_dirs(c)
	  || finalise_start_dirs(c)
	  || finalise_fschg_dirs(c))
		return -1;

	if(finalise_keep_args(c))
		return -1;

	if(burp_mode==BURP_MODE_SERVER)
	{
		if(!get_strlist(c[OPT_LISTEN]))
		{
			logp("Need at least one 'listen' config.\n");
			return -1;
		}
		if(finalise_server_max_children(c,
			OPT_LISTEN, OPT_MAX_CHILDREN)
		  || finalise_server_max_children(c,
			OPT_LISTEN_STATUS, OPT_MAX_STATUS_CHILDREN))
				return -1;
	}
	if(burp_mode==BURP_MODE_CLIENT)
	{
		if(finalise_client_ports(c))
			return -1;
	}

	if((s_script_notify=get_int(c[OPT_S_SCRIPT_NOTIFY])))
	{
		set_int(c[OPT_S_SCRIPT_PRE_NOTIFY], s_script_notify);
		set_int(c[OPT_S_SCRIPT_POST_NOTIFY], s_script_notify);
	}

	// These override the specific pre/post script paths with the general
	// one. For example, if 'server_script' is set, its value is used for
	// 'server_script_pre' and 'server_script_post'.
	if(pre_post_override(c[OPT_B_SCRIPT],
		c[OPT_B_SCRIPT_PRE], c[OPT_B_SCRIPT_POST])
	  || pre_post_override(c[OPT_R_SCRIPT],
		c[OPT_R_SCRIPT_PRE], c[OPT_R_SCRIPT_POST])
	  || pre_post_override(c[OPT_S_SCRIPT],
		c[OPT_S_SCRIPT_PRE], c[OPT_S_SCRIPT_POST])
	// And these do the same for the script arguments.
	  || setup_script_arg_overrides(c[OPT_B_SCRIPT_ARG],
		c[OPT_B_SCRIPT_PRE_ARG], c[OPT_B_SCRIPT_POST_ARG])
	  || setup_script_arg_overrides(c[OPT_R_SCRIPT_ARG],
		c[OPT_R_SCRIPT_PRE_ARG], c[OPT_R_SCRIPT_POST_ARG])
	  || setup_script_arg_overrides(c[OPT_S_SCRIPT_ARG],
		c[OPT_S_SCRIPT_PRE_ARG], c[OPT_S_SCRIPT_POST_ARG]))
			return -1;

	// We are now done with these. Clear them, otherwise they interfere.
	set_string(c[OPT_S_SCRIPT], NULL);
	set_strlist(c[OPT_S_SCRIPT_ARG], NULL);
	return 0;
}

static int conf_finalise_global_only(const char *conf_path, struct conf **confs)
{
	int r=0;

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

static int conf_load_lines_from_file(const char *conf_path, struct conf **confs)
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

#ifndef UTEST
static
#endif
int conf_load_lines_from_buf(const char *buf, struct conf **c)
{
	int ret=0;
	int line=0;
	char *tok=NULL;
	char *copy=NULL;

	if(!buf) return 0;

	if(!(copy=strdup_w(buf, __func__))) return -1;
	if(!(tok=strtok(copy, "\n")))
	{
		logp("unable to parse conf buffer\n");
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

	return ret;
}

/* The server runs this when parsing a restore file on the server. Called
   elsewhere too. */
int conf_parse_incexcs_path(struct conf **c, const char *path)
{
	free_incexcs(c);
	if(conf_load_lines_from_file(path, c)
	  || conf_finalise(c))
		return -1;
	return 0;
}

/* The client runs this when the server overrides the incexcs. */
int conf_parse_incexcs_buf(struct conf **c, const char *incexc)
{
	free_incexcs(c);
	if(conf_load_lines_from_buf(incexc, c)
	  || conf_finalise(c))
		return -1;
	return 0;
}

/* The client runs this when the server overrides the incexcs for restore. */
int conf_parse_incexcs_srestore(struct conf **c, const char *incexc)
{
	int ret=-1;
	char *rp=NULL;
	char *oldprefix=NULL;
	char *srvprefix=NULL;
	char *newprefix=NULL;
	const char *rpfield=c[OPT_RESTOREPREFIX]->field;

	if(!(rp=get_string(c[OPT_RESTOREPREFIX])))
	{
		logp("The client side must specify a %s!\n", rpfield);
		goto end;
	}
	if(!(oldprefix=strdup_w(rp, __func__)))
		goto end;

	free_incexcs(c);
	set_string(c[OPT_RESTOREPREFIX], NULL);
	if(conf_load_lines_from_buf(incexc, c)
	  || conf_finalise(c))
		goto end;

	if((srvprefix=get_string(c[OPT_RESTOREPREFIX])))
	{
		if(has_dot_component(srvprefix))
		{
			logp("The server gave %s '%s', which is not allowed!",
				rpfield, srvprefix);
			goto end;
		}
		if(!strcmp(oldprefix, "/"))
		{
			// Avoid double slash.
			if(!(newprefix=prepend_s("", srvprefix)))
				goto end;
		}
		else
		{
			if(!(newprefix=prepend_s(oldprefix, srvprefix)))
				goto end;
		}
		if(set_string(c[OPT_RESTOREPREFIX], newprefix))
			goto end;
		if(build_path_w(newprefix))
			goto end;
	}
	else
	{
		if(set_string(c[OPT_RESTOREPREFIX], oldprefix))
			goto end;
	}
	ret=0;
end:
	free_w(&oldprefix);
	free_w(&newprefix);
	return ret;
}

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
				set_uint64_t(cc[i], get_uint64_t(globalc[i]));
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
			case CT_E_RSHASH:
				set_e_rshash(cc[i], get_e_rshash(globalc[i]));
				break;
			case CT_STRLIST:
				// Done later.
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

static int append_strlist(struct conf *dst, struct conf *src)
{
	struct strlist *s;
	for(s=get_strlist(src); s; s=s->next)
		if(add_to_strlist(dst, s->path, s->flag))
			return -1;
	return 0;
}

// Instead of adding onto the end of the list, this replaces the list.
static int conf_set_from_global_arg_list_overrides(struct conf **globalc,
	struct conf **cc)
{
	int i=0;
	for(i=0; i<OPT_MAX; i++)
	{
		if(cc[i]->conf_type!=CT_STRLIST) continue;
		if(!(cc[i]->flags & CONF_FLAG_CC_OVERRIDE)) continue;
		if(cc[i]->flags & CONF_FLAG_STRLIST_REPLACE)
		{
			// If there was no cc[i] strlist set, use the global.
			if(!get_strlist(cc[i])
			  && append_strlist(cc[i], globalc[i]))
				return -1;
		}
		else
		{
			struct conf tmpconf;
			// A bit painful.
			tmpconf.conf_type=cc[i]->conf_type;
			tmpconf.flags=cc[i]->flags;
			memset(&tmpconf.data, 0, sizeof(tmpconf.data));
			if(append_strlist(&tmpconf, globalc[i])
			  || append_strlist(&tmpconf, cc[i]))
				return -1;
			set_strlist(cc[i], get_strlist(&tmpconf));
		}
	}
	return 0;
}

static int conf_init_save_cname_and_version(struct conf **cconfs)
{
	int ret=-1;
	char *cname=NULL;
	char *cversion=NULL;
	char *orig_cname=get_string(cconfs[OPT_CNAME]);
	char *orig_cversion=get_string(cconfs[OPT_PEER_VERSION]);

	if((orig_cname && !(cname=strdup_w(orig_cname, __func__)))
	  || (orig_cversion
	    && !(cversion=strdup_w(orig_cversion, __func__))))
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

static int do_conf_load_overrides(struct conf **globalcs, struct conf **cconfs,
	const char *path, const char *buf)
{
	// Some client settings can be globally set in the server conf and
	// overridden in the client specific conf.
	if(conf_set_from_global(globalcs, cconfs)) return -1;
	if(buf) { if(conf_load_lines_from_buf(buf, cconfs)) return -1; }
	else { if(conf_load_lines_from_file(path, cconfs)) return -1; }
	if(conf_set_from_global_arg_list_overrides(globalcs, cconfs)
	  || conf_finalise(cconfs))
		return -1;
	return 0;
}

#ifndef UTEST
static
#endif
int conf_load_overrides(struct conf **globalcs, struct conf **cconfs,
	const char *path)
{
	return do_conf_load_overrides(globalcs, cconfs, path, NULL);
}

int cname_valid(const char *cname)
{
	if(!cname) return 0;
	if(cname[0]=='.'
	  || strchr(cname, '/') // Avoid path attacks.
	  || strchr(cname, '\\') // Be cautious of backslashes too.
	  // I am told that emacs tmp files end with '~'.
	  || cname[strlen(cname)-1]=='~')
		return 0;
	return 1;
}

int conf_load_clientconfdir(struct conf **globalcs, struct conf **cconfs)
{
	int ret=-1;
	char *path=NULL;
	const char *cname=NULL;

	if(conf_init_save_cname_and_version(cconfs)) goto end;
	cname=get_string(cconfs[OPT_CNAME]);
	if(!cname_valid(cname))
	{
		logp("client name '%s' is not valid\n", cname);
		goto end;
	}

	if(!(path=prepend_s(get_string(globalcs[OPT_CLIENTCONFDIR]), cname)))
		goto end;
	ret=conf_load_overrides(globalcs, cconfs, path);
end:
	free_w(&path);
	return ret;
}

static int do_load_global_only(struct conf **globalcs,
	const char *path, const char *buf)
{
	if(set_string(globalcs[OPT_CONFFILE], path)) return -1;
	if(buf) { if(conf_load_lines_from_buf(buf, globalcs)) return -1; }
	else { if(conf_load_lines_from_file(path, globalcs)) return -1; }
	if(conf_finalise(globalcs)
	  || conf_finalise_global_only(path, globalcs))
		return -1;
	return 0;

}

int conf_load_global_only(const char *path, struct conf **globalcs)
{
	return do_load_global_only(globalcs, path, NULL);
}

static int restore_client_allowed(struct conf **cconfs, struct conf **sconfs)
{
	struct strlist *r;
	for(r=get_strlist(sconfs[OPT_SUPER_CLIENTS]); r; r=r->next)
		if(!strcmp(r->path, get_string(cconfs[OPT_CNAME])))
			return 2;
	for(r=get_strlist(sconfs[OPT_RESTORE_CLIENTS]); r; r=r->next)
		if(!strcmp(r->path, get_string(cconfs[OPT_CNAME])))
			return 1;
	logp("Access to client is not allowed: %s\n",
		get_string(sconfs[OPT_CNAME]));
	return 0;
}

int conf_switch_to_orig_client(struct conf **globalcs,
	struct conf **cconfs, const char *orig_client)
{
	int ret=-1;
	int is_super=0;
	struct conf **sconfs=NULL;

	// If we are already the wanted client, no need to switch.
	if(!strcmp(get_string(cconfs[OPT_CNAME]), orig_client))
		return 0;

	if(!(sconfs=confs_alloc())
	  || confs_init(sconfs)) goto end;
	if(set_string(sconfs[OPT_CNAME], orig_client))
		goto end;
	logp("Client wants to switch to client: %s\n",
		get_string(sconfs[OPT_CNAME]));

	if(conf_load_clientconfdir(globalcs, sconfs))
	{
		logp("Could not load alternate config: %s",
			get_string(sconfs[OPT_CNAME]));
		goto end;
	}
	set_int(sconfs[OPT_SEND_CLIENT_CNTR],
		get_int(cconfs[OPT_SEND_CLIENT_CNTR]));

	switch(restore_client_allowed(cconfs, sconfs))
	{
		case 1:
			break;
		case 2:
			is_super=1;
			break;
		default:
			goto end;
	}

	// Restore client can never force backup.
	set_int(sconfs[OPT_CLIENT_CAN_FORCE_BACKUP], 0);

	if(is_super)
	{
		set_int(sconfs[OPT_CLIENT_CAN_DELETE],
			get_int(cconfs[OPT_CLIENT_CAN_DELETE]));
		set_int(sconfs[OPT_CLIENT_CAN_DIFF],
			get_int(cconfs[OPT_CLIENT_CAN_DIFF]));
		set_int(sconfs[OPT_CLIENT_CAN_LIST],
			get_int(cconfs[OPT_CLIENT_CAN_LIST]));
		set_int(sconfs[OPT_CLIENT_CAN_MONITOR],
			get_int(cconfs[OPT_CLIENT_CAN_MONITOR]));
		set_int(sconfs[OPT_CLIENT_CAN_RESTORE],
			get_int(cconfs[OPT_CLIENT_CAN_RESTORE]));
		set_int(sconfs[OPT_CLIENT_CAN_VERIFY],
			get_int(cconfs[OPT_CLIENT_CAN_VERIFY]));
	}
	else
	{
		// For the rest of the client_can things, do not allow them on
		// orig_client if we do not have them ourselves.
		if(!get_int(cconfs[OPT_CLIENT_CAN_DELETE]))
			set_int(sconfs[OPT_CLIENT_CAN_DELETE], 0);
		if(!get_int(cconfs[OPT_CLIENT_CAN_DIFF]))
			set_int(sconfs[OPT_CLIENT_CAN_DIFF], 0);
		if(!get_int(cconfs[OPT_CLIENT_CAN_LIST]))
			set_int(sconfs[OPT_CLIENT_CAN_LIST], 0);
		if(!get_int(cconfs[OPT_CLIENT_CAN_MONITOR]))
			set_int(sconfs[OPT_CLIENT_CAN_MONITOR], 0);
		if(!get_int(cconfs[OPT_CLIENT_CAN_RESTORE]))
			set_int(sconfs[OPT_CLIENT_CAN_RESTORE], 0);
		if(!get_int(cconfs[OPT_CLIENT_CAN_VERIFY]))
			set_int(sconfs[OPT_CLIENT_CAN_VERIFY], 0);
	}

	if(set_string(sconfs[OPT_CONNECT_CLIENT],
		get_string(cconfs[OPT_CONNECT_CLIENT])))
			goto end;
	if(set_string(sconfs[OPT_RESTORE_PATH],
		get_string(cconfs[OPT_RESTORE_PATH])))
			goto end;
	if(set_string(cconfs[OPT_RESTORE_PATH], NULL))
		goto end;
	set_cntr(sconfs[OPT_CNTR], get_cntr(cconfs));
	set_cntr(cconfs[OPT_CNTR], NULL);
	confs_free_content(cconfs);
	confs_init(cconfs);
	confs_memcpy(cconfs, sconfs);
	confs_null(sconfs);
	if(set_string(cconfs[OPT_SUPER_CLIENT],
		get_string(cconfs[OPT_CNAME]))) goto end;
	if(set_string(cconfs[OPT_ORIG_CLIENT],
		get_string(cconfs[OPT_CNAME]))) goto end;

	logp("Switched to client %s\n", get_string(cconfs[OPT_CNAME]));
	ret=0;
end:
	confs_free(&sconfs);
	return ret;
}

char *config_default_path(void)
{
	static char path[256]="";
#ifdef HAVE_WIN32
	char *pfenv=NULL;

	// Burp used to always install to 'C:/Program Files/Burp/', but as
	// of 1.3.11, it changed to %PROGRAMFILES%. Still want the old way
	// to work though. So check %PROGRAMFILES% first, then fall back.
	if((pfenv=getenv("PROGRAMFILES")))
	{
		struct stat statp;
		snprintf(path, sizeof(path), "%s/%s/%s.conf",
			pfenv, PACKAGE_NAME, PACKAGE_TARNAME);
		if(!lstat(path, &statp)
		  && !S_ISDIR(statp.st_mode))
			return path;
	}
	snprintf(path, sizeof(path), "C:/Program Files/%s/%s.conf",
		PACKAGE_NAME, PACKAGE_TARNAME);
#else
	snprintf(path, sizeof(path), "%s/%s.conf",
		SYSCONFDIR, PACKAGE_TARNAME);
#endif
	return path;
}
