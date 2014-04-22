#include "burp.h"
#include "prog.h"
#include "counter.h"
#include "conf.h"
#include "msg.h"
#include "handy.h"
#include "cmd.h"
#include "asyncio.h"
#include "strlist.h"
#include "incexc_send.h"

static int send_incexc_str(const char *pre, const char *str)
{
	char *tosend=NULL;
	int rc=0;
	if(!str) return 0;
	if(!(tosend=prepend(pre, str, strlen(str), " = ")))
		rc=-1;
	if(!rc && async_write_str(CMD_GEN, tosend))
	{
		logp("Error in async_write_str when sending incexc\n");
		rc=-1;
	}
	if(tosend)
		free(tosend);
	return rc;
}

static int send_incexc_int(const char *pre, int myint)
{
	char tmp[64]="";
	snprintf(tmp, sizeof(tmp), "%d", myint);
	return send_incexc_str(pre, tmp);
}

static int send_incexc_long(const char *pre, long mylong)
{
	char tmp[32]="";
	snprintf(tmp, sizeof(tmp), "%lu", mylong);
	return send_incexc_str(pre, tmp);
}

static int send_incexc_from_strlist(const char *prepend_on, const char *prepend_off, int count, struct strlist **list)
{
	int i=0;
	for(i=0; i<count; i++)
	{
		if(send_incexc_str(list[i]->flag?prepend_on:prepend_off,
			list[i]->path))
				return -1;
	}
	return 0;
}

static int do_sends(struct config *conf)
{
	if(  send_incexc_from_strlist("include", "exclude",
		conf->iecount, conf->incexcdir)
	  || send_incexc_from_strlist("include_glob", "include_glob",
		conf->igcount, conf->incglob)
	  || send_incexc_from_strlist("cross_filesystem", "cross_filesystem",
		conf->fscount, conf->fschgdir)
	  || send_incexc_from_strlist("nobackup", "nobackup",
		conf->nbcount, conf->nobackup)
	  || send_incexc_from_strlist("include_ext", "include_ext",
		conf->incount, conf->incext)
	  || send_incexc_from_strlist("exclude_ext", "exclude_ext",
		conf->excount, conf->excext)
	  || send_incexc_from_strlist("include_regex", "include_regex",
		conf->ircount, conf->increg)
	  || send_incexc_from_strlist("exclude_regex", "exclude_regex",
		conf->ercount, conf->excreg)
	  || send_incexc_from_strlist("exclude_fs", "exclude_fs",
		conf->exfscount, conf->excfs)
	  || send_incexc_from_strlist("exclude_comp", "exclude_comp",
		conf->excmcount, conf->excom)
	  || send_incexc_from_strlist("read_fifo", "read_fifo",
		conf->ffcount, conf->fifos)
	  || send_incexc_from_strlist("read_blockdev", "read_blockdev",
		conf->bdcount, conf->blockdevs)
	  || send_incexc_int("cross_all_filesystems",
		conf->cross_all_filesystems)
	  || send_incexc_int("split_vss", conf->split_vss)
	  || send_incexc_int("strip_vss", conf->strip_vss)
	  || send_incexc_int("atime", conf->atime)
	  || send_incexc_int("read_all_fifos", conf->read_all_fifos)
	  || send_incexc_long("min_file_size", conf->min_file_size)
	  || send_incexc_long("max_file_size", conf->max_file_size)
	  || send_incexc_str("vss_drives", conf->vss_drives))
		return -1;
	return 0;
}

static int do_sends_restore(struct config *conf)
{
	if(  send_incexc_from_strlist("include", "exclude",
		conf->iecount, conf->incexcdir)
	  || send_incexc_str("orig_client", conf->orig_client)
	  || send_incexc_str("backup", conf->backup)
	  || send_incexc_str("restoreprefix", conf->restoreprefix)
	  || send_incexc_str("regex", conf->regex)
	  || send_incexc_int("overwrite", conf->overwrite)
	  || send_incexc_long("strip", conf->strip))
		return -1;
	return 0;
}

static int do_finish(const char *endreqstr, const char *endrepstr)
{
	int ret=-1;
	char cmd='\0';
	char *buf=NULL;
	size_t len=0;
	if(async_write_str(CMD_GEN, endreqstr))
		goto end;
	if(async_read(&cmd, &buf, &len))
		goto end;
	if(cmd==CMD_GEN)
	{
		if(strcmp(buf, endrepstr))
		{
			logp("unexpected response to %s: %s\n", endreqstr,
				buf);
			goto end;
		}
	}
	else
	{
		logp("unexpected response to %s: %c:%s\n", endreqstr,
			cmd, buf);
		goto end;
	}
	ret=0;
end:
	if(buf) free(buf);
	return ret;
}

static int do_start(const char *reqstr, const char *repstr)
{
	int ret=-1;
	char cmd='\0';
	char *buf=NULL;
	size_t len=0;

	if(async_write_str(CMD_GEN, reqstr))
		goto end;
	if(async_read(&cmd, &buf, &len))
		goto end;
	if(cmd==CMD_GEN)
	{
		if(strcmp(buf, repstr))
		{
			logp("unexpected response to %s: %s\n", reqstr, buf);
			goto end;
		}
	}
	else
	{
		logp("unexpected response to %s: %c:%s\n", reqstr, cmd, buf);
		goto end;
	}
	ret=0;
end:
	if(buf) free(buf);
	return ret;
}

int incexc_send_client(struct config *conf, struct cntr *p1cntr)
{
	if(do_start("incexc", "incexc ok")
	  || do_sends(conf)
	  || do_finish("incexc end", "incexc end ok"))
		return -1;
	return 0;
}

int incexc_send_server(struct config *conf, struct cntr *p1cntr)
{
	/* 'sincexc' and 'sincexc ok' have already been exchanged,
	   so go straight into doing the sends. */
	if(do_sends(conf)
	  || do_finish("sincexc end", "sincexc end ok"))
		return -1;
	return 0;
}

int incexc_send_server_restore(struct config *conf, struct cntr *p1cntr)
{
	/* 'srestore' and 'srestore ok' have already been exchanged,
	   so go straight into doing the sends. */
	if(do_sends_restore(conf)
	  || do_finish("srestore end", "srestore end ok"))
		return -1;
	return 0;
}
