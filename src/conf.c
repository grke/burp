#include "burp.h"
#include "conf.h"
#include "prog.h"
#include "find.h"
#include "log.h"
#include "strlist.h"

static int conf_error(const char *config_path, int line)
{
	logp("%s: parse error on line %d\n", config_path, line);
	return -1;
}

void init_config(struct config *conf)
{
	conf->mode=MODE_UNSET;
	conf->port=NULL;
	conf->status_port=NULL;
	conf->keep=0;
	conf->hardlinked_archive=0;
	conf->working_dir_recovery_method=NULL;
	conf->clientconfdir=NULL;
	conf->cname=NULL;
	conf->directory=NULL;
	conf->lockfile=NULL;
	conf->logfile=NULL;
	conf->password=NULL;
	conf->server=NULL;
	conf->startdir=NULL;
	conf->incexcdir=NULL;
	conf->fschgdir=NULL;
	conf->sdcount=0;
	conf->iecount=0;
	conf->fscount=0;
	conf->ffcount=0;
	conf->fifos=NULL;
	conf->cross_all_filesystems=0;
	conf->read_all_fifos=0;
	conf->ssl_cert_ca=NULL;
        conf->ssl_cert=NULL;
        conf->ssl_cert_password=NULL;
	conf->ssl_dhfile=NULL;
	conf->ssl_peer_cn=NULL;
	conf->encryption_password=NULL;
	conf->max_children=0;
	conf->librsync=1;
	conf->compression=9;
	conf->client_lockdir=NULL;

	conf->timer_script=NULL;
	conf->timer_arg=NULL;
	conf->tacount=0;

	conf->notify_success_script=NULL;
	conf->notify_success_arg=NULL;
	conf->nscount=0;

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

	conf->backup_script=NULL;
	conf->backup_script_arg=NULL;
	conf->bscount=0;
	conf->restore_script=NULL;
	conf->restore_script_arg=NULL;
	conf->rscount=0;
}

void free_config(struct config *conf)
{
	if(!conf) return;
	if(conf->clientconfdir) free(conf->clientconfdir);
	if(conf->cname) free(conf->cname);
	if(conf->directory) free(conf->directory);
	if(conf->lockfile) free(conf->lockfile);
	if(conf->logfile) free(conf->logfile);
	if(conf->password) free(conf->password);
	if(conf->server) free(conf->server);
	if(conf->working_dir_recovery_method)
		free(conf->working_dir_recovery_method);
 	if(conf->ssl_cert_ca) free(conf->ssl_cert_ca);
        if(conf->ssl_cert) free(conf->ssl_cert);
        if(conf->ssl_cert_password) free(conf->ssl_cert_password);
        if(conf->ssl_dhfile) free(conf->ssl_dhfile);
        if(conf->ssl_peer_cn) free(conf->ssl_peer_cn);
        if(conf->encryption_password) free(conf->encryption_password);
	if(conf->client_lockdir) free(conf->client_lockdir);
	strlists_free(conf->startdir, conf->sdcount);
	strlists_free(conf->incexcdir, conf->iecount);
	strlists_free(conf->fschgdir, conf->fscount);
	strlists_free(conf->fifos, conf->ffcount);

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

	if(conf->backup_script) free(conf->backup_script);
	if(conf->restore_script) free(conf->restore_script);
	strlists_free(conf->backup_script_arg, conf->bscount);
	strlists_free(conf->restore_script_arg, conf->rscount);

	init_config(conf);
}

static int get_conf_val(const char *field, const char *value, const char *want, char **dest)
{
	if(!strcmp(field, want) && !(*dest=strdup(value)))
	{
		logp("could not strdup %s value: %s\n", field, value);
		return -1;
	}
	return 0;
}

static int get_pair(char *buf, char **field, char **value)
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

int load_config(const char *config_path, struct config *conf, bool loadall)
{
	int i=0;
	int r=0;
	int line=0;
	FILE *fp=NULL;
	char buf[256]="";
	struct strlist **sdlist=NULL;
	struct strlist **ielist=NULL;
	struct strlist **fslist=NULL;
	struct strlist **fflist=NULL;
	struct strlist **talist=NULL;
	struct strlist **nslist=NULL;
	struct strlist **nflist=NULL;
	struct strlist **bprelist=NULL;
	struct strlist **bpostlist=NULL;
	struct strlist **rprelist=NULL;
	struct strlist **rpostlist=NULL;
	struct strlist **bslist=NULL;
	struct strlist **rslist=NULL;
	int have_include=0;
	int got_timer_args=conf->tacount;
	int got_ns_args=conf->nscount;
	int got_nf_args=conf->nfcount;

	//logp("in load_config\n");

	if(!(fp=fopen(config_path, "r")))
	{
		logp("could not open '%s' for reading.\n", config_path);
		return -1;
	}
	while(fgets(buf, sizeof(buf), fp))
	{
		char *field=NULL;
		char *value=NULL;
		line++;

		if(get_pair(buf, &field, &value))
			return conf_error(config_path, line);
		if(!field || !value) continue;

		if(!strcmp(field, "mode"))
		{
			if(!strcmp(value, "server"))
				conf->mode=MODE_SERVER;
			else if(!strcmp(value, "client"))
				conf->mode=MODE_CLIENT;
			else
				return conf_error(config_path, line);
		}
		else if(!strcmp(field, "keep"))
		{
			conf->keep=atoi(value);
			if(!conf->keep)
				return conf_error(config_path, line);
		}
		else if(!strcmp(field, "hardlinked_archive"))
		{
			conf->hardlinked_archive=atoi(value);
		}
		else if(!strcmp(field, "librsync"))
		{
			conf->librsync=atoi(value);
		}
		else if(!strcmp(field, "compression"))
		{
			char *cp=NULL;
			cp=value;
			if(!strncmp(value, "gzip", strlen("gzip")))
			{
				char *cp=NULL;
				cp=value+strlen("gzip")+1;
			}
			if(strlen(cp)!=1 || !isdigit(*cp))
				return conf_error(config_path, line);

			conf->compression=atoi(value);
		}
		else if(!strcmp(field, "working_dir_recovery_method"))
		{
			if(get_conf_val(field, value,
			  "working_dir_recovery_method",
			  &(conf->working_dir_recovery_method))) return -1;
			if(strcmp(conf->working_dir_recovery_method, "delete")
			  && strcmp(conf->working_dir_recovery_method, "use")
			  && strcmp(conf->working_dir_recovery_method, "merge"))
			{
			  logp("unknown working_dir_recovery_method: %s\n",
				conf->working_dir_recovery_method);
			}
		}
		else if(!strcmp(field, "cross_all_filesystems"))
		{
			conf->cross_all_filesystems=atoi(value);
		}
		else if(!strcmp(field, "read_all_fifos"))
		{
			conf->read_all_fifos=atoi(value);
		}
		else if(!strcmp(field, "max_children"))
		{
			if((conf->max_children=atoi(value))<=0)
				return conf_error(config_path, line);
		}
		else if(!strcmp(field, "backup_script_post_run_on_fail"))
		{
			conf->backup_script_post_run_on_fail=atoi(value);
		}
		else if(!strcmp(field, "restore_script_post_run_on_fail"))
		{
			conf->restore_script_post_run_on_fail=atoi(value);
		}
		else
		{
			if(get_conf_val(field, value,
			  "port", &(conf->port))) return -1;
			if(get_conf_val(field, value,
			  "status_port", &(conf->status_port))) return -1;
			if(get_conf_val(field, value,
			  "ssl_cert_ca", &(conf->ssl_cert_ca))) return -1;
			if(get_conf_val(field, value,
			  "ssl_cert", &(conf->ssl_cert))) return -1;
			if(get_conf_val(field, value,
			  "ssl_cert_password", &(conf->ssl_cert_password)))
				return -1;
			if(get_conf_val(field, value,
			  "ssl_dhfile", &(conf->ssl_dhfile))) return -1;
			if(get_conf_val(field, value,
			  "ssl_peer_cn", &(conf->ssl_peer_cn))) return -1;
			if(get_conf_val(field, value,
			  "clientconfdir", &(conf->clientconfdir))) return -1;
			if(get_conf_val(field, value,
			  "cname", &(conf->cname))) return -1;
			if(get_conf_val(field, value,
			  "directory", &(conf->directory))) return -1;
			if(get_conf_val(field, value,
			  "client_lockdir", &(conf->client_lockdir))) return -1;
			if(get_conf_val(field, value,
			  "lockfile", &(conf->lockfile))) return -1;
			// "pidfile" is a synonym for "lockfile".
			if(get_conf_val(field, value,
			  "pidfile", &(conf->lockfile))) return -1;
			if(get_conf_val(field, value,
			  "logfile", &(conf->logfile))) return -1;
			if(get_conf_val(field, value,
			  "password", &(conf->password))) return -1;
			if(get_conf_val(field, value,
			  "server", &(conf->server))) return -1;
			if(get_conf_val(field, value,
			  "encryption_password", &(conf->encryption_password)))
				return -1;
			if(get_conf_val_args(field, value,
				"include",
				NULL, NULL, &(conf->iecount),
				&ielist, 1)) return -1;
			if(get_conf_val_args(field, value,
				"exclude",
				NULL, NULL, &(conf->iecount),
				&ielist, 0)) return -1;
			if(get_conf_val_args(field, value,
				"cross_filesystem",
				NULL, NULL, &(conf->fscount),
				&fslist, 0)) return -1;
			if(get_conf_val_args(field, value,
				"read_fifo",
				NULL, NULL, &(conf->ffcount),
				&fflist, 0)) return -1;
			if(get_conf_val(field, value,
			  "timer_script", &(conf->timer_script))) return -1;
			if(get_conf_val_args(field, value,
				"timer_arg",
				&(conf->timer_arg),
				&got_timer_args, &(conf->tacount),
				&talist, 0)) return -1;
			if(get_conf_val(field, value,
			  "notify_success_script",
			  &(conf->notify_success_script))) return -1;
			if(get_conf_val_args(field, value,
				"notify_success_arg",
				&(conf->notify_success_arg),
				&got_ns_args, &(conf->nscount),
				&nslist, 0)) return -1;
			if(get_conf_val(field, value,
			  "notify_failure_script",
			  &(conf->notify_failure_script))) return -1;
			if(get_conf_val_args(field, value,
				"notify_failure_arg",
				&(conf->notify_failure_arg),
				&got_nf_args, &(conf->nfcount),
				&nflist, 0)) return -1;
			if(get_conf_val(field, value,
			  "backup_script_pre",
			  &(conf->backup_script_pre))) return -1;
			if(get_conf_val_args(field, value,
				"backup_script_pre_arg",
				&(conf->backup_script_pre_arg),
				NULL, &(conf->bprecount),
				&bprelist, 0)) return -1;
			if(get_conf_val(field, value,
			  "backup_script_post",
			  &(conf->backup_script_post))) return -1;
			if(get_conf_val_args(field, value,
				"backup_script_post_arg",
				&(conf->backup_script_post_arg),
				NULL, &(conf->bpostcount),
				&bpostlist, 0)) return -1;
			if(get_conf_val(field, value,
			  "restore_script_pre",
			  &(conf->restore_script_pre))) return -1;
			if(get_conf_val_args(field, value,
				"restore_script_pre_arg",
				&(conf->restore_script_pre_arg),
				NULL, &(conf->rprecount),
				&rprelist, 0)) return -1;
			if(get_conf_val(field, value,
			  "restore_script_post",
			  &(conf->restore_script_post))) return -1;
			if(get_conf_val_args(field, value,
				"restore_script_post_arg",
				&(conf->restore_script_post_arg),
				NULL, &(conf->rpostcount),
				&rpostlist, 0)) return -1;

			if(get_conf_val(field, value,
			  "backup_script",
			  &(conf->backup_script))) return -1;
			if(get_conf_val_args(field, value,
				"backup_script_arg",
				&(conf->backup_script_arg),
				NULL, &(conf->bscount),
				&bslist, 0)) return -1;
			if(get_conf_val(field, value,
			  "restore_script",
			  &(conf->restore_script))) return -1;
			if(get_conf_val_args(field, value,
				"restore_script_arg",
				&(conf->restore_script_arg),
				NULL, &(conf->rscount),
				&rslist, 0)) return -1;
		}
	}
	fclose(fp);

	if(conf->ffcount) qsort(fflist, conf->ffcount,
		sizeof(*fflist),
		(int (*)(const void *, const void *))strlist_sort);
	conf->fifos=fflist;

	if(conf->fscount) qsort(fslist, conf->fscount,
		sizeof(*fslist),
		(int (*)(const void *, const void *))strlist_sort);
	conf->fschgdir=fslist;

	if(conf->iecount) qsort(ielist, conf->iecount,
		sizeof(*ielist),
		(int (*)(const void *, const void *))strlist_sort);
	conf->incexcdir=ielist;

	// This decides which directories to start backing up, and which
	// are subdirectories which don't need to be started separately.
	for(i=0; i<conf->iecount; i++)
	{
		if(strchr(ielist[i]->path, '\\'))
			logp("WARNING: Please use forward slashes '/' instead of backslashes '\\' in your include/exclude paths.\n");
		if(ielist[i]->flag) have_include++;
		if(!i)
		{
			// ielist is sorted - the first entry is one that
			// can be backed up
			if(!ielist[i]->flag)
			{
				logp("Top level should not be an exclude: %s\n",
					ielist[i]->path);
				return -1;
			}
			if(strlist_add(&sdlist, &(conf->sdcount),
				ielist[i]->path, 1)) return -1;
			continue;
		}
		// Ensure that we do not backup the same directory twice.
		if(!strcmp(ielist[i]->path, ielist[i-1]->path))
		{
			logp("Directory appears twice in config: %s\n",
				ielist[i]->path);
			return -1;
		}
		// If it is not a subdirectory of the most recent start point,
		// we have found another start point.
		if(!is_subdir(sdlist[(conf->sdcount)-1]->path, ielist[i]->path))
		{
			if(strlist_add(&sdlist, &(conf->sdcount),
				ielist[i]->path, 1)) return -1;
		}
	}
	conf->startdir=sdlist;

	if(!got_timer_args) conf->timer_arg=talist;
	if(!got_ns_args) conf->notify_success_arg=nslist;
	if(!got_nf_args) conf->notify_failure_arg=nflist;

	// If backup_script is set, override both post and pre settings.
	// TODO: make a function to avoid repeating this stuff.
	if(conf->backup_script)
	{
		if(conf->backup_script_pre)
			free(conf->backup_script_pre);
		if(conf->backup_script_post)
			free(conf->backup_script_post);
		if(!(conf->backup_script_pre=strdup(conf->backup_script))
		  || !(conf->backup_script_post=strdup(conf->backup_script)))
		{
			logp("out of memory\n");
			return -1;
		}
		free(conf->backup_script);
		conf->backup_script=NULL;
	}
	if(bslist)
	{
		strlists_free(bprelist, conf->bprecount);
		strlists_free(bpostlist, conf->bpostcount);
		conf->bprecount=0;
		conf->bpostcount=0;
		for(i=0; i<conf->bscount; i++)
		{
			if(strlist_add(&bprelist,
				&(conf->bprecount),
				bslist[i]->path, 0)) return -1;
			if(strlist_add(&bpostlist,
				&(conf->bpostcount),
				bslist[i]->path, 0)) return -1;
		}
	}
	// If restore_script is set, override both post and pre settings.
	// TODO: make a function to avoid repeating this stuff.
	if(conf->restore_script)
	{
		if(conf->restore_script_pre)
			free(conf->restore_script_pre);
		if(conf->restore_script_post)
			free(conf->restore_script_post);
		if(!(conf->restore_script_pre=strdup(conf->restore_script))
		  || !(conf->restore_script_post=strdup(conf->restore_script)))
		{
			logp("out of memory\n");
			return -1;
		}
		free(conf->restore_script);
		conf->restore_script=NULL;
	}
	if(rslist)
	{
		strlists_free(rprelist, conf->rprecount);
		strlists_free(rpostlist, conf->rpostcount);
		conf->rprecount=0;
		conf->rpostcount=0;
		for(i=0; i<conf->rscount; i++)
		{
			if(strlist_add(&rprelist,
				&(conf->rprecount),
				rslist[i]->path, 0)) return -1;
			if(strlist_add(&rpostlist,
				&(conf->rpostcount),
				rslist[i]->path, 0)) return -1;
		}
	}

	conf->backup_script_pre_arg=bprelist;
	conf->backup_script_post_arg=bpostlist;
	conf->restore_script_pre_arg=rprelist;
	conf->restore_script_post_arg=rpostlist;

	if(!loadall) return 0;

	if(!conf->port)
	{
		logp("%s: port unset\n", config_path);
		r--;
	}
	// Let the caller check the 'keep' value.

	if(!conf->ssl_cert_password) conf->ssl_cert_password=strdup("");

	switch(conf->mode)
	{
		case MODE_SERVER:
			if(!conf->directory)
			  { logp("%s: directory unset\n", config_path); r--; }
			if(!conf->clientconfdir)
			  { logp("%s: clientconfdir unset\n", config_path); r--; }
			if(!conf->working_dir_recovery_method)
			  { logp("%s: working_dir_recovery_method unset\n", config_path); r--; }
			if(!conf->ssl_cert)
			  { logp("%s: ssl_cert unset\n", config_path); r--; }
			if(!conf->ssl_cert_ca)
			  { logp("%s: ssl_cert_ca unset\n", config_path); r--; }
			if(!conf->ssl_dhfile)
			  { logp("%s: ssl_dhfile unset\n", config_path); r--; }
			if(conf->encryption_password)
			  { logp("%s: encryption_password should not be set on the server!\n", config_path); r--; }
			if(!conf->status_port) // carry on if not set.
			  { logp("%s: status_port unset\n", config_path); }
			if(!conf->max_children)
			{
				logp("%s: max_children unset - using 5\n",
					config_path);
				conf->max_children=5;
			}
			break;
		case MODE_CLIENT:
			if(!conf->cname)
			  { logp("%s: client name unset\n", config_path); r--; }
			if(!conf->password)
			  { logp("%s: password unset\n", config_path); r--; }
			if(!conf->server)
			  { logp("%s: server unset\n", config_path); r--; }
			if(!conf->ssl_cert)
			  { logp("%s: ssl_cert unset\n", config_path); r--; }
			if(!conf->ssl_cert_ca)
			  { logp("%s: ssl_cert_ca unset\n", config_path); r--; }
			if(!conf->ssl_peer_cn)
			  { logp("%s: ssl_peer_cn unset\n", config_path); r--; }
			if(!conf->lockfile)
			  { logp("%s: lockfile unset\n", config_path); r--; }
			if(!have_include)
			{
				logp("%s: no 'include' paths configured\n",
					config_path);
				r--;
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
				if(!conf->sdcount)
				{
					logp("Found no starting paths!\n");
					return -1;
				}
			}
			break;
		case MODE_UNSET:
		default:
		  logp("%s: mode unset - should be 'server' or 'client'\n",
			config_path);
		  r--;
		  break;
	}
	//if(!r) logp("ok\n");

	// If client_lockdir not set, use conf->directory.
	if(!conf->client_lockdir && conf->directory
	  && !(conf->client_lockdir=strdup(conf->directory)))
	{
		logp("out of memory\n");
		return -1;
	}

	return r;
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
				src[i]->path, 0)) return -1;
		}
		*dst=list;
	}
	return 0;
}

/* Remember to update the list in the man page when you change these.*/
int set_client_global_config(struct config *conf, struct config *cconf)
{
	cconf->keep=conf->keep;
	cconf->hardlinked_archive=conf->hardlinked_archive;
	cconf->librsync=conf->librsync;
	cconf->compression=conf->compression;
	if(set_global_str(&(cconf->directory), conf->directory))
		return -1;
	if(set_global_str(&(cconf->working_dir_recovery_method),
		conf->working_dir_recovery_method)) return -1;
	if(set_global_str(&(cconf->timer_script), conf->timer_script))
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

	return 0;
}
