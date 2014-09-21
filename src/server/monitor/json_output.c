#include "include.h"

static int write_all(struct asfd *asfd)
{
	int ret=-1;
	size_t len;
	const unsigned char *buf;
	yajl_gen_get_buf(yajl, &buf, &len);
	ret=asfd->write_strn(asfd, CMD_GEN /* not used */,
		(const char *)buf, len);
	yajl_gen_clear(yajl);
	return ret;
}

static int json_start(struct asfd *asfd)
{
	if(!yajl)
	{
		if(!(yajl=yajl_gen_alloc(NULL)))
			return -1;
		yajl_gen_config(yajl, yajl_gen_beautify, 1);
	}
	if(yajl_map_open_w()
	  || yajl_gen_str_w("clients")
	  || yajl_array_open_w())
		return -1;
	return 0;
}

static int json_end(struct asfd *asfd)
{
	int ret=-1;
	if(yajl_array_close_w()
	  || yajl_map_close_w())
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

static gzFile open_backup_log(struct bu *bu, const char *logfile)
{
	gzFile zp=NULL;
	char *path=NULL;

	char logfilereal[32]="";
	if(!strcmp(logfile, "backup"))
		snprintf(logfilereal, sizeof(logfilereal), "log");
	else if(!strcmp(logfile, "restore"))
		snprintf(logfilereal, sizeof(logfilereal), "restorelog");
	else if(!strcmp(logfile, "verify"))
		snprintf(logfilereal, sizeof(logfilereal), "verifylog");

	if(!(path=prepend_s(bu->path, logfilereal)))
		goto end;
	if(!(zp=gzopen_file(path, "rb")))
	{
		if(astrcat(&path, ".gz", __func__)
		  || !(zp=gzopen_file(path, "rb")))
			goto end;
	}
end:
	free_w(&path);
	return zp;

}

static int flag_wrap_str_zp(struct bu *bu, uint16_t flag, const char *field,
	const char *logfile)
{
	int ret=-1;
	gzFile zp=NULL;
	if(!flag_matches(bu, flag)
	  || !logfile || strcmp(logfile, field))
		return 0;
	if(!(zp=open_backup_log(bu, logfile))) goto end;
	if(yajl_gen_str_w(field)) goto end;
	if(yajl_array_open_w()) goto end;
	if(zp)
	{
		char *cp=NULL;
		char buf[1024]="";
		while(gzgets(zp, buf, sizeof(buf)))
		{
			if((cp=strrchr(buf, '\n'))) *cp='\0';
			if(yajl_gen_str_w(buf))
				goto end;
		}
	}
	if(yajl_array_close_w()) goto end;
	ret=0;
end:
	gzclose_fp(&zp);
	return ret;
}

static int json_send_backup(struct asfd *asfd, struct cstat *cstat,
	struct bu *bu, int print_flags,
	const char *logfile, const char *browse,
	struct conf *conf)
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
	if(print_flags
	  && (bu->flags & (BU_LOG_BACKUP|BU_LOG_RESTORE|BU_LOG_VERIFY)))
	{
		if(yajl_gen_str_w("logs")
		  || yajl_map_open_w()
		  || yajl_gen_str_w("list")
	  	  || yajl_array_open_w()
		  || flag_wrap_str(bu, BU_LOG_BACKUP, "backup")
		  || flag_wrap_str(bu, BU_LOG_RESTORE, "restore")
		  || flag_wrap_str(bu, BU_LOG_VERIFY, "verify")
	  	  || yajl_array_close_w())
			return -1;
		if(logfile)
		{
			if(flag_wrap_str_zp(bu,
				BU_LOG_BACKUP, "backup", logfile)
			  || flag_wrap_str_zp(bu,
				BU_LOG_RESTORE, "restore", logfile)
			  || flag_wrap_str_zp(bu,
				BU_LOG_VERIFY, "verify", logfile))
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
			if(browse_manifest(asfd, cstat, bu, browse, conf))
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
	const char *status=cstat_status_to_str(cstat);

	if(yajl_map_open_w()
	  || yajl_gen_str_pair_w("name", cstat->name)
	  || yajl_gen_str_pair_w("status", status)
	  || yajl_gen_str_w("backups")
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
	struct cstat *cstat, struct bu *bu, const char *logfile,
	const char *browse, struct conf *conf)
{
	int ret=-1;
	if(json_send_client_start(asfd, cstat)) return -1;
	ret=json_send_backup(asfd, cstat,
		bu, 1 /* print flags */, logfile, browse, conf);
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
	struct conf *conf)
{
	int ret=-1;
	struct cstat *c;

	if(json_start(asfd)) goto end;

	if(cstat && bu)
	{
		if(json_send_client_backup(asfd, cstat, bu, logfile, browse,
			conf)) goto end;
	}
	else if(cstat)
	{
		if(json_send_client_backup_list(asfd, cstat)) goto end;
	}
	else for(c=clist; c; c=c->next)
	{
		if(!c->permitted) continue;
		if(json_send_client_backup(asfd, c, c->bu,
			NULL, NULL, NULL))
				goto end;
	}

	ret=0;
end:
	if(json_end(asfd)) return -1;
	return ret;
}

int json_from_sbuf(struct sbuf *sb)
{
	return yajl_map_open_w()
	  || yajl_gen_str_pair_w("name", sb->path.buf)
	  || yajl_gen_int_pair_w("dev", sb->statp.st_dev)
	  || yajl_gen_int_pair_w("ino", sb->statp.st_ino)
	  || yajl_gen_int_pair_w("mode", sb->statp.st_mode)
	  || yajl_gen_int_pair_w("nlink", sb->statp.st_nlink)
	  || yajl_gen_int_pair_w("uid", sb->statp.st_uid)
	  || yajl_gen_int_pair_w("gid", sb->statp.st_gid)
	  || yajl_gen_int_pair_w("rdev", sb->statp.st_rdev)
	  || yajl_gen_int_pair_w("size", sb->statp.st_size)
	  || yajl_gen_int_pair_w("blksize", sb->statp.st_blksize)
	  || yajl_gen_int_pair_w("blocks", sb->statp.st_blocks)
	  || yajl_gen_int_pair_w("atime", sb->statp.st_atime)
	  || yajl_gen_int_pair_w("ctime", sb->statp.st_ctime)
	  || yajl_gen_int_pair_w("mtime", sb->statp.st_mtime)
	  || yajl_map_close_w();
}
