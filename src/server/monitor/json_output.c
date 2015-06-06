#include "include.h"
#include "../../bu.h"
#include "../../cmd.h"

static int pretty_print=1;

void json_set_pretty_print(int value)
{
	pretty_print=value;
}

static int write_all(struct asfd *asfd)
{
	int ret=-1;
	size_t w=0;
	size_t len=0;
	const unsigned char *buf;

	yajl_gen_get_buf(yajl, &buf, &len);
	while(len)
	{
		w=len;
		if(w>ASYNC_BUF_LEN) w=ASYNC_BUF_LEN;
		if((ret=asfd->write_strn(asfd, CMD_GEN /* not used */,
			(const char *)buf, w)))
				break;
		buf+=w;
		len-=w;
	}
	if(!ret && !pretty_print)
		ret=asfd->write_strn(asfd, CMD_GEN /* not used */, "\n", 1);

	yajl_gen_clear(yajl);
	return ret;
}

static int json_start(struct asfd *asfd)
{
	if(!yajl)
	{
		if(!(yajl=yajl_gen_alloc(NULL)))
			return -1;
		yajl_gen_config(yajl, yajl_gen_beautify, pretty_print);
	}
	if(yajl_map_open_w()) return -1;
	return 0;
}

static int json_clients(void)
{
	if(yajl_gen_str_w("clients")
	  || yajl_array_open_w())
		return -1;
	return 0;
}

static int json_clients_end(void)
{
	if(yajl_array_close_w()) return -1;
	return 0;
}

static int json_end(struct asfd *asfd)
{
	int ret=-1;
	if(yajl_map_close_w())
		goto end;
	ret=write_all(asfd);
end:
	yajl_gen_free(yajl);
	yajl=NULL;
	return ret;
}

static long timestamp_to_long(const char *buf)
{
	struct tm tm;
	const char *b=NULL;
	if(!(b=strchr(buf, ' '))) return 0;
	memset(&tm, 0, sizeof(struct tm));
	if(!strptime(b, " %Y-%m-%d %H:%M:%S", &tm)) return 0;
	// Tell mktime to use the daylight savings time setting
	// from the time zone of the system.
	tm.tm_isdst=-1;
	return (long)mktime(&tm);
}

static int flag_matches(struct bu *bu, uint16_t flag)
{
	return (bu && (bu->flags & flag));
}

static int flag_wrap_str(struct bu *bu, uint16_t flag, const char *field)
{
	if(!flag_matches(bu, flag)) return 0;
	return yajl_gen_str_w(field);
}

static struct fzp *open_backup_log(struct bu *bu, const char *logfile)
{
	char *path=NULL;
	struct fzp *fzp=NULL;

	char logfilereal[32]="";
	if(!strcmp(logfile, "backup"))
		snprintf(logfilereal, sizeof(logfilereal), "log");
	else if(!strcmp(logfile, "restore"))
		snprintf(logfilereal, sizeof(logfilereal), "restorelog");
	else if(!strcmp(logfile, "verify"))
		snprintf(logfilereal, sizeof(logfilereal), "verifylog");
	else if(!strcmp(logfile, "backup_stats"))
		snprintf(logfilereal, sizeof(logfilereal), "backup_stats");
	else if(!strcmp(logfile, "restore_stats"))
		snprintf(logfilereal, sizeof(logfilereal), "restore_stats");
	else if(!strcmp(logfile, "verify_stats"))
		snprintf(logfilereal, sizeof(logfilereal), "verify_stats");

	if(!(path=prepend_s(bu->path, logfilereal)))
		goto end;
	if(!(fzp=fzp_gzopen(path, "rb")))
	{
		if(astrcat(&path, ".gz", __func__)
		  || !(fzp=fzp_gzopen(path, "rb")))
			goto end;
	}
end:
	free_w(&path);
	return fzp;

}

static int flag_wrap_str_zp(struct bu *bu, uint16_t flag, const char *field,
	const char *logfile)
{
	int ret=-1;
	struct fzp *fzp=NULL;
	if(!flag_matches(bu, flag)
	  || !logfile || strcmp(logfile, field))
		return 0;
	if(!(fzp=open_backup_log(bu, logfile))) goto end;
	if(yajl_gen_str_w(field)) goto end;
	if(yajl_array_open_w()) goto end;
	if(fzp)
	{
		char *cp=NULL;
		char buf[1024]="";
		while(fzp_gets(fzp, buf, sizeof(buf)))
		{
			if((cp=strrchr(buf, '\n'))) *cp='\0';
			if(yajl_gen_str_w(buf))
				goto end;
		}
	}
	if(yajl_array_close_w()) goto end;
	ret=0;
end:
	fzp_close(&fzp);
	return ret;
}

static int do_counters(struct cntr *cntr)
{
	static char type[2];
	struct cntr_ent *e;

	cntr->ent[(uint8_t)CMD_TIMESTAMP_END]->count
		=(unsigned long long)time(NULL);
	if(yajl_gen_str_w("counters")
	  || yajl_array_open_w()) return -1;
	for(e=cntr->list; e; e=e->next)
	{
		if(e->flags & CNTR_SINGLE_FIELD)
		{
			if(!e->count) continue;
			snprintf(type, sizeof(type), "%c", e->cmd);
			if(yajl_map_open_w()
			  || yajl_gen_str_pair_w("name", e->field)
			  || yajl_gen_str_pair_w("type", type)
			  || yajl_gen_int_pair_w("count", e->count)
			  || yajl_map_close_w())
				return -1;
		}
		else if(e->flags & CNTR_TABULATE)
		{
			if(!e->count
			  && !e->changed
			  && !e->same
			  && !e->deleted
			  && !e->phase1)
				continue;
			snprintf(type, sizeof(type), "%c", e->cmd);
			if(yajl_map_open_w()
			  || yajl_gen_str_pair_w("name", e->field)
			  || yajl_gen_str_pair_w("type", type)
			  || yajl_gen_int_pair_w("count", e->count)
			  || yajl_gen_int_pair_w("changed", e->changed)
			  || yajl_gen_int_pair_w("same", e->same)
			  || yajl_gen_int_pair_w("deleted", e->deleted)
			  || yajl_gen_int_pair_w("scanned", e->phase1)
			  || yajl_map_close_w())
				return -1;
		}
	}

  	if(yajl_array_close_w())
		return -1;
	return 0;
}

static int json_send_backup(struct asfd *asfd, struct cstat *cstat,
	struct bu *bu, int print_flags,
	const char *logfile, const char *browse,
	struct conf **confs)
{
	long long bno=0;
	long long timestamp=0;
	if(!bu) return 0;
	bno=(long long)bu->bno;
	timestamp=(long long)timestamp_to_long(bu->timestamp);

	if(yajl_map_open_w()
	  || yajl_gen_int_pair_w("number", bno)
	  || yajl_gen_int_pair_w("timestamp", timestamp)
	  || yajl_gen_str_w("flags")
	  || yajl_array_open_w()
	  || flag_wrap_str(bu, BU_HARDLINKED, "hardlinked")
	  || flag_wrap_str(bu, BU_DELETABLE, "deletable")
	  || flag_wrap_str(bu, BU_WORKING, "working")
	  || flag_wrap_str(bu, BU_FINISHING, "finishing")
	  || flag_wrap_str(bu, BU_CURRENT, "current")
	  || flag_wrap_str(bu, BU_MANIFEST, "manifest")
	  || yajl_array_close_w())
		return -1;
	if(bu->flags & (BU_WORKING|BU_FINISHING))
	{
		if(do_counters(cstat->cntr)) return -1;
	}
	if(print_flags
	  && (bu->flags & (BU_LOG_BACKUP|BU_LOG_RESTORE|BU_LOG_VERIFY
		|BU_STATS_BACKUP|BU_STATS_RESTORE|BU_STATS_VERIFY)))
	{
		if(yajl_gen_str_w("logs")
		  || yajl_map_open_w()
		  || yajl_gen_str_w("list")
	  	  || yajl_array_open_w()
		  || flag_wrap_str(bu, BU_LOG_BACKUP, "backup")
		  || flag_wrap_str(bu, BU_LOG_RESTORE, "restore")
		  || flag_wrap_str(bu, BU_LOG_VERIFY, "verify")
		  || flag_wrap_str(bu, BU_STATS_BACKUP, "backup_stats")
		  || flag_wrap_str(bu, BU_STATS_RESTORE, "restore_stats")
		  || flag_wrap_str(bu, BU_STATS_VERIFY, "verify_stats")
	  	  || yajl_array_close_w())
			return -1;
		if(logfile)
		{
			if(flag_wrap_str_zp(bu,
				BU_LOG_BACKUP, "backup", logfile)
			  || flag_wrap_str_zp(bu,
				BU_LOG_RESTORE, "restore", logfile)
			  || flag_wrap_str_zp(bu,
				BU_LOG_VERIFY, "verify", logfile)
			  || flag_wrap_str_zp(bu,
				BU_STATS_BACKUP, "backup_stats", logfile)
			  || flag_wrap_str_zp(bu,
				BU_STATS_RESTORE, "restore_stats", logfile)
			  || flag_wrap_str_zp(bu,
				BU_STATS_VERIFY, "verify_stats", logfile))
					return -1;
		}
		if(yajl_map_close_w())
			return -1;
		if(browse)
		{
			if(yajl_gen_str_w("browse")) return -1;
			if(yajl_map_open_w()) return -1;
			if(yajl_gen_str_pair_w("directory", browse)) return -1;
			if(yajl_gen_str_w("entries")) return -1;
			if(yajl_array_open_w()) return -1;
			if(browse_manifest(asfd, cstat, bu, browse, confs))
				return -1;
			if(yajl_array_close_w()) return -1;
			if(yajl_map_close_w()) return -1;

		}
	}
	if(yajl_gen_map_close(yajl)!=yajl_gen_status_ok)
		return -1;

	return 0;
}

static int json_send_client_start(struct asfd *asfd, struct cstat *cstat)
{
	const char *run_status=run_status_to_str(cstat);

	if(yajl_map_open_w()
	  || yajl_gen_str_pair_w("name", cstat->name)
	  || yajl_gen_str_pair_w("run_status", run_status))
		return -1;
	if(cstat->run_status==RUN_STATUS_RUNNING)
	{
		if(yajl_gen_str_pair_w("phase",
			cntr_status_to_str(cstat->cntr))) return -1;
	}
	if(yajl_gen_str_w("backups")
	  || yajl_array_open_w())
		return -1;
	return 0;
}

static int json_send_client_end(struct asfd *asfd)
{
	if(yajl_array_close_w()
	  || yajl_map_close_w())
		return -1;
	return 0;
}

static int json_send_client_backup(struct asfd *asfd,
	struct cstat *cstat, struct bu *bu1, struct bu *bu2,
	const char *logfile, const char *browse, struct conf **confs)
{
	int ret=-1;
	if(json_send_client_start(asfd, cstat)) return -1;
	if((ret=json_send_backup(asfd, cstat,
		bu1, 1 /* print flags */, logfile, browse, confs)))
			goto end;
	if((ret=json_send_backup(asfd, cstat,
		bu2, 1 /* print flags */, logfile, browse, confs)))
			goto end;
end:
	if(json_send_client_end(asfd)) ret=-1;
	return ret;
}

static int json_send_client_backup_list(struct asfd *asfd, struct cstat *cstat)
{
	int ret=-1;
	struct bu *bu;
	if(json_send_client_start(asfd, cstat)) return -1;
	for(bu=cstat->bu; bu; bu=bu->prev)
	{
		if(json_send_backup(asfd, cstat,
			bu, 1 /* print flags */, NULL, NULL, NULL)) goto end;
	}
	ret=0;
end:
	if(json_send_client_end(asfd)) ret=-1;
	return ret;
}

int json_send(struct asfd *asfd, struct cstat *clist, struct cstat *cstat,
	struct bu *bu, const char *logfile, const char *browse,
	struct conf **confs)
{
	int ret=-1;
	struct cstat *c;

	if(json_start(asfd)
	  || json_clients())
		goto end;

	if(cstat && bu)
	{
		if(json_send_client_backup(asfd, cstat, bu, NULL,
			logfile, browse, confs)) goto end;
	}
	else if(cstat)
	{
		if(json_send_client_backup_list(asfd, cstat)) goto end;
	}
	else for(c=clist; c; c=c->next)
	{
		if(!c->permitted) continue;
		if(json_send_client_backup(asfd, c,
			bu_find_current(c->bu),
			bu_find_working_or_finishing(c->bu),
			NULL, NULL, NULL))
				goto end;
	}

	ret=0;
end:
	if(json_clients_end()
	  || json_end(asfd)) return -1;
	return ret;
}

int json_cntr_to_file(struct asfd *asfd, struct cntr *cntr)
{
	int ret=-1;
	if(json_start(asfd)
	  || do_counters(cntr))
		goto end;
	ret=0;
end:
	if(json_end(asfd)) return -1;
	return ret;
}

int json_from_statp(const char *path, struct stat *statp)
{
	return yajl_map_open_w()
	  || yajl_gen_str_pair_w("name", path)
	  || yajl_gen_int_pair_w("dev", statp->st_dev)
	  || yajl_gen_int_pair_w("ino", statp->st_ino)
	  || yajl_gen_int_pair_w("mode", statp->st_mode)
	  || yajl_gen_int_pair_w("nlink", statp->st_nlink)
	  || yajl_gen_int_pair_w("uid", statp->st_uid)
	  || yajl_gen_int_pair_w("gid", statp->st_gid)
	  || yajl_gen_int_pair_w("rdev", statp->st_rdev)
	  || yajl_gen_int_pair_w("size", statp->st_size)
	  || yajl_gen_int_pair_w("blksize", statp->st_blksize)
	  || yajl_gen_int_pair_w("blocks", statp->st_blocks)
	  || yajl_gen_int_pair_w("atime", statp->st_atime)
	  || yajl_gen_int_pair_w("ctime", statp->st_ctime)
	  || yajl_gen_int_pair_w("mtime", statp->st_mtime)
	  || yajl_map_close_w();
}

int json_send_warn(struct asfd *asfd, const char *msg)
{
	if(json_start(asfd)
	  || yajl_gen_str_pair_w("warning", msg)
	  || json_end(asfd)) return -1;
	return 0;
}
