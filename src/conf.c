#include "burp.h"
#include "conf.h"
#include "prog.h"
#include "find.h"
#include "log.h"

static int conf_error(const char *config_path, int line)
{
	logp("%s: parse error on line %d\n", config_path, line);
	return -1;
}

void init_config(struct config *conf)
{
	conf->mode=MODE_UNSET;
	conf->port=0;
	conf->status_port=0;
	conf->keep=0;
	conf->hardlinked_archive=0;
	conf->working_dir_recovery_method=NULL;
	conf->clientconfdir=NULL;
	conf->cname=NULL;
	conf->directory=NULL;
	conf->lockfile=NULL;
	conf->password=NULL;
	conf->server=NULL;
	conf->startdir=NULL;
	conf->incexcdir=NULL;
	conf->fschgdir=NULL;
	conf->sdcount=0;
	conf->iecount=0;
	conf->fscount=0;
	conf->cross_all_filesystems=0;
	conf->ssl_cert_ca=NULL;
        conf->ssl_cert=NULL;
        conf->ssl_cert_password=NULL;
	conf->ssl_dhfile=NULL;
	conf->ssl_peer_cn=NULL;
	conf->encryption_password=NULL;
	conf->max_children=0;

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
	conf->backup_script_post=NULL;
	conf->backup_script_post_run_on_fail=0;

	conf->restore_script_pre=NULL;
	conf->restore_script_post=NULL;
	conf->restore_script_post_run_on_fail=0;
}

static void free_backupdirs(struct backupdir **bd, int count)
{
	int b=0;
	if(bd)
	{
		for(b=0; b<count; b++)
		{
			if(bd[b])
			{
				if(bd[b]->path) free(bd[b]->path);
				free(bd[b]);
			}
		}
		free(bd);
	}
}

void free_config(struct config *conf)
{
	if(!conf) return;
	if(conf->clientconfdir) free(conf->clientconfdir);
	if(conf->cname) free(conf->cname);
	if(conf->directory) free(conf->directory);
	if(conf->lockfile) free(conf->lockfile);
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
	free_backupdirs(conf->startdir, conf->sdcount);
	free_backupdirs(conf->incexcdir, conf->iecount);
	free_backupdirs(conf->fschgdir, conf->fscount);

	if(conf->timer_script) free(conf->timer_script);
	free_backupdirs(conf->timer_arg, conf->tacount);

	if(conf->notify_success_script) free(conf->notify_success_script);
	free_backupdirs(conf->notify_success_arg, conf->nscount);

	if(conf->notify_failure_script) free(conf->notify_failure_script);
	free_backupdirs(conf->notify_failure_arg, conf->nfcount);

	if(conf->backup_script_pre) free(conf->backup_script_pre);
	if(conf->backup_script_post) free(conf->backup_script_post);
	if(conf->restore_script_pre) free(conf->restore_script_pre);
	if(conf->restore_script_post) free(conf->restore_script_post);

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

static int add_backup_dir(struct backupdir ***bdlist, int *count, char *path, int include)
{
	//int b=0;
	struct backupdir *bdnew=NULL;
	struct backupdir **bdtmp=NULL;
	if(!path)
	{
		logp("add_backup_dir called with NULL path!\n");
		return -1;
	}
	if(!(bdtmp=(struct backupdir **)realloc(*bdlist,
		((*count)+1)*sizeof(struct backupdir *))))
	{
		logp("out of memory in add_backup_dir()\n");
		return -1;
	}
	*bdlist=bdtmp;
	if(!(bdnew=(struct backupdir *)malloc(sizeof(struct backupdir))))
	{
		logp("out of memory in add_backup_dir()\n");
		return -1;
	}
	bdnew->include=include;
	bdnew->path=strdup(path);
	(*bdlist)[(*count)++]=bdnew;

	//for(b=0; b<*count; b++)
	//	printf("now: %d %s\n", b, (*bdlist)[b]->path);
	return 0;
}

static int myalphasort(struct backupdir **a, struct backupdir **b)
{
	return pathcmp((*a)->path, (*b)->path);
}

int load_config(const char *config_path, struct config *conf, bool loadall)
{
	int i=0;
	int r=0;
	int line=0;
	FILE *fp=NULL;
	char buf[256]="";
	struct backupdir **sdlist=NULL;
	struct backupdir **ielist=NULL;
	struct backupdir **fslist=NULL;
	struct backupdir **talist=NULL;
	struct backupdir **nslist=NULL;
	struct backupdir **nflist=NULL;
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
		else if(!strcmp(field, "port"))
		{
			conf->port=atoi(value);
			if(conf->port<=0)
				return conf_error(config_path, line);
		}
		else if(!strcmp(field, "status_port"))
		{
			conf->status_port=atoi(value);
			if(conf->status_port<=0)
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
			char *tmp=NULL;
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
			  "lockfile", &(conf->lockfile))) return -1;
			if(get_conf_val(field, value,
			  "password", &(conf->password))) return -1;
			if(get_conf_val(field, value,
			  "server", &(conf->server))) return -1;
			if(get_conf_val(field, value,
			  "encryption_password", &(conf->encryption_password)))
				return -1;
			if(get_conf_val(field, value,
			  "include", &tmp)) return -1;
			if(tmp)
			{
				if(strchr(tmp, '\\'))
					logp("WARNING: Please use forward slashes '/' instead of backslashes '\\' in your include paths.\n");
				if(add_backup_dir(&ielist, &(conf->iecount),
					tmp, 1)) return -1;
				have_include++;
				free(tmp); tmp=NULL;
			}
			if(get_conf_val(field, value,
			  "exclude", &tmp)) return -1;
			if(tmp)
			{
				if(strchr(tmp, '\\'))
					logp("WARNING: Please use forward slashes '/' instead of backslashes '\\' in your exclude paths.\n");
				if(add_backup_dir(&ielist, &(conf->iecount),
					tmp, 0)) return -1;
				free(tmp); tmp=NULL;
			}
			if(get_conf_val(field, value,
			  "cross_filesystem", &tmp)) return -1;
			if(tmp)
			{
				if(add_backup_dir(&fslist, &(conf->fscount),
					tmp, 0)) return -1;
				free(tmp); tmp=NULL;
			}
			if(get_conf_val(field, value,
			  "timer_script", &(conf->timer_script))) return -1;
			if(get_conf_val(field, value,
			  "timer_arg", &tmp)) return -1;
			if(tmp)
			{
				if(got_timer_args)
				{
					free_backupdirs(conf->timer_arg,
						conf->tacount);
					got_timer_args=0;
					conf->timer_arg=NULL;
					conf->tacount=0;
				}
				if(add_backup_dir(&talist, &(conf->tacount),
					tmp, 0)) return -1;
				free(tmp); tmp=NULL;
			}
			if(get_conf_val(field, value,
			  "notify_success_script", &(conf->notify_success_script))) return -1;
			if(get_conf_val(field, value,
			  "notify_success_arg", &tmp)) return -1;
			if(tmp)
			{
				if(got_ns_args)
				{
					free_backupdirs(conf->notify_success_arg,
						conf->nscount);
					got_ns_args=0;
					conf->notify_success_arg=NULL;
					conf->nscount=0;
				}
				if(add_backup_dir(&nslist, &(conf->nscount),
					tmp, 0)) return -1;
				free(tmp); tmp=NULL;
			}
			if(get_conf_val(field, value,
			  "notify_failure_script", &(conf->notify_failure_script))) return -1;
			if(get_conf_val(field, value,
			  "notify_failure_arg", &tmp)) return -1;
			if(tmp)
			{
				if(got_nf_args)
				{
					free_backupdirs(conf->notify_failure_arg,
						conf->nfcount);
					got_nf_args=0;
					conf->notify_failure_arg=NULL;
					conf->nfcount=0;
				}
				if(add_backup_dir(&nflist, &(conf->nfcount),
					tmp, 0)) return -1;
				free(tmp); tmp=NULL;
			}

			if(get_conf_val(field, value,
			  "backup_script_pre", &(conf->backup_script_pre)))
				return -1;
			if(get_conf_val(field, value,
			  "backup_script_post", &(conf->backup_script_post)))
				return -1;
			if(get_conf_val(field, value,
			  "restore_script_pre", &(conf->restore_script_pre)))
				return -1;
			if(get_conf_val(field, value,
			  "restore_script_post", &(conf->restore_script_post)))
				return -1;
		}
	}
	fclose(fp);

	if(conf->fscount) qsort(fslist, conf->fscount,
		sizeof(*fslist),
		(int (*)(const void *, const void *))myalphasort);
	conf->fschgdir=fslist;

	if(conf->iecount) qsort(ielist, conf->iecount,
		sizeof(*ielist),
		(int (*)(const void *, const void *))myalphasort);
	conf->incexcdir=ielist;

	// This decides which directories to start backing up, and which
	// are subdirectories which don't need to be started separately.
	for(i=0; i<conf->iecount; i++)
	{
		if(!i)
		{
			// ielist is sorted - the first entry is one that
			// can be backed up
			if(!ielist[i]->include)
			{
				logp("Top level should not be an exclude: %s\n",
					ielist[i]->path);
				return -1;
			}
			if(add_backup_dir(&sdlist, &(conf->sdcount),
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
			if(add_backup_dir(&sdlist, &(conf->sdcount),
				ielist[i]->path, 1)) return -1;
		}
	}
	conf->startdir=sdlist;

	if(!got_timer_args) conf->timer_arg=talist;
	if(!got_ns_args) conf->notify_success_arg=nslist;
	if(!got_nf_args) conf->notify_failure_arg=nflist;

	if(!loadall) return 0;

	if(conf->port<=0)
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
			if(conf->status_port<=0) // carry on if not set.
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
						conf->incexcdir[b]->include?
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

static int set_global_arglist(struct backupdir ***dst, struct backupdir **src, int *dstcount, int srccount)
{
	if(!*dst && src)
	{
		int i=0;
		struct backupdir **list=NULL;
		for(i=0; i<srccount; i++)
		{
			if(add_backup_dir(&list, dstcount,
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
