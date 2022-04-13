#include "../../burp.h"
#include "../../alloc.h"
#include "../../asfd.h"
#include "../../async.h"
#include "../../bu.h"
#include "../../cmd.h"
#include "../../cstat.h"
#include "../../fzp.h"
#include "../../handy.h"
#include "../../iobuf.h"
#include "../../prepend.h"
#include "../../strlist.h"
#include "../../yajl_gen_w.h"
#include "../timestamp.h"
#include "browse.h"
#include "json_output.h"

static int pretty_print=1;
static long version_2_1_8=0;

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
	struct iobuf wbuf;

	yajl_gen_get_buf(yajl, &buf, &len);
	while(len)
	{
		w=len;
		if(w>ASYNC_BUF_LEN) w=ASYNC_BUF_LEN;
		iobuf_set(&wbuf, CMD_GEN /* not used */, (char *)buf, w);
		if((ret=asfd->write(asfd, &wbuf)))
			break;
		buf+=w;
		len-=w;
	}
	if(!ret && !pretty_print)
	{
		iobuf_set(&wbuf, CMD_GEN /* not used */, (char *)"\n", 1);
		ret=asfd->write(asfd, &wbuf);
	}

	yajl_gen_clear(yajl);
	return ret;
}

static int json_start(void)
{
	if(!yajl)
	{
		if(!(yajl=yajl_gen_alloc(NULL)))
			return -1;
		yajl_gen_config(yajl, yajl_gen_beautify, pretty_print);
		if(!version_2_1_8)
			version_2_1_8=version_to_long("2.1.8");
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

#ifndef UTEST
	cntr->ent[(uint8_t)CMD_TIMESTAMP_END]->count=(uint64_t)time(NULL);
#endif
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

static int json_send_backup(struct cstat *cstat, struct bu *bu,
	int print_flags, const char *logfile, const char *browse,
	int use_cache, long peer_version)
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
		if(peer_version<=version_2_1_8)
		{
			if(do_counters(cstat->cntrs))
				return -1;
		}
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
			if(browse_manifest(cstat, bu, browse, use_cache))
				return -1;
			if(yajl_array_close_w()) return -1;
			if(yajl_map_close_w()) return -1;

		}
	}
	if(yajl_gen_map_close(yajl)!=yajl_gen_status_ok)
		return -1;

	return 0;
}

static int str_array(const char *field, struct cstat *cstat)
{
	struct strlist *s=NULL;
	if(!cstat->labels) return 0;
	if(yajl_gen_str_w(field)
	  || yajl_array_open_w())
		return -1;
	for(s=cstat->labels; s; s=s->next)
		if(yajl_gen_str_w(s->path))
			return -1;
	if(yajl_array_close_w())
		return -1;
	return 0;
}

static int do_children(struct cntr *cntrs)
{
	struct cntr *c;
	if(yajl_gen_str_w("children")
	  || yajl_array_open_w())
		return -1;
	for(c=cntrs; c; c=c->next)
	{
		if(yajl_map_open_w()
		  || yajl_gen_int_pair_w("pid", c->pid)
		  || yajl_gen_int_pair_w("backup", c->bno)
		  || yajl_gen_str_pair_w("action", cntr_status_to_action_str(c))
		  || yajl_gen_str_pair_w("phase", cntr_status_to_str(c)))
			return -1;
		if(do_counters(c))
			return -1;
		if(yajl_map_close_w())
			return -1;
	}
	if(yajl_array_close_w())
		return -1;
	return 0;
}

static int json_send_client_start(struct cstat *cstat, long peer_version)
{
	const char *run_status=run_status_to_str(cstat);

	if(yajl_map_open_w()
	  || yajl_gen_str_pair_w("name", cstat->name))
		return -1;
	if(str_array("labels", cstat))
		return -1;
	if(yajl_gen_str_pair_w("run_status", run_status))
		return -1;
	if(yajl_gen_int_pair_w("protocol", 1))
		return -1;
	if(peer_version>version_2_1_8)
	{
		if(cstat->cntrs
		  && do_children(cstat->cntrs))
			return -1;
	}
	else if(cstat->cntrs)
	{
		// Best effort.
		if(yajl_gen_str_pair_w("phase",
			cntr_status_to_str(cstat->cntrs)))
				return -1;
	}
	if(yajl_gen_str_w("backups")
	  || yajl_array_open_w())
		return -1;
	return 0;
}

static int json_send_client_end(void)
{
	if(yajl_array_close_w()
	  || yajl_map_close_w())
		return -1;
	return 0;
}

static int json_send_client_backup(struct cstat *cstat, struct bu *bu1,
	struct bu *bu2, const char *logfile, const char *browse, int use_cache,
	long peer_version)
{
	int ret=-1;
	if(json_send_client_start(cstat, peer_version))
		return -1;
	if((ret=json_send_backup(cstat, bu1,
		1 /* print flags */, logfile, browse, use_cache, peer_version)))
			goto end;
	if((ret=json_send_backup(cstat, bu2,
		1 /* print flags */, logfile, browse, use_cache, peer_version)))
			goto end;
end:
	if(json_send_client_end()) ret=-1;
	return ret;
}

static int json_send_client_backup_list(struct cstat *cstat, int use_cache,
	long peer_version)
{
	int ret=-1;
	struct bu *bu;
	if(json_send_client_start(cstat, peer_version))
		return -1;
	for(bu=cstat->bu; bu; bu=bu->prev)
	{
		if(json_send_backup(cstat, bu,
			1 /* print flags */, NULL, NULL,
			use_cache, peer_version))
				goto end;
	}
	ret=0;
end:
	if(json_send_client_end()) ret=-1;
	return ret;
}

int json_send(struct asfd *asfd, struct cstat *clist, struct cstat *cstat,
	struct bu *bu, const char *logfile, const char *browse,
	int use_cache, long peer_version)
{
	int ret=-1;
	struct cstat *c;

	if(json_start()
	  || json_clients())
		goto end;

	if(cstat && bu)
	{
		if(json_send_client_backup(cstat, bu, NULL,
			logfile, browse, use_cache, peer_version))
				goto end;
	}
	else if(cstat)
	{
		if(json_send_client_backup_list(cstat,
			use_cache, peer_version))
				goto end;
	}
	else for(c=clist; c; c=c->next)
	{
		if(!c->permitted) continue;
		if(json_send_client_backup(c,
			bu_find_current(c->bu),
			bu_find_working_or_finishing(c->bu),
			NULL, NULL, use_cache, peer_version))
				goto end;
	}

	ret=0;
end:
	if(json_clients_end()
	  || json_end(asfd)) return -1;
	return ret;
}

int json_cntr(struct asfd *asfd, struct cntr *cntr)
{
	int ret=-1;
	if(json_start()
	  || do_counters(cntr))
		goto end;
	ret=0;
end:
	if(json_end(asfd)) return -1;
	return ret;
}

int json_from_entry(const char *path, const char *link, struct stat *statp)
{
	return yajl_map_open_w()
	  || yajl_gen_str_pair_w("name", path)
	  || yajl_gen_str_pair_w("link", link? link:"")
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

int json_send_msg(struct asfd *asfd, const char *field, const char *msg)
{
	int save;
	int ret=0;

	// Turn off pretty printing so that we get it on one line.
	save=pretty_print;
	pretty_print=0;

	if(json_start()
	  || yajl_gen_str_pair_w(field, msg)
	  || json_end(asfd))
		ret=-1;

	pretty_print=save;

	return ret;
}

int json_send_warn(struct asfd *asfd, const char *msg)
{
	return json_send_msg(asfd, "warning", msg);
}
