#include "burp.h"
#include "prog.h"
#include "counter.h"
#include "conf.h"
#include "msg.h"
#include "handy.h"
#include "cmd.h"
#include "asyncio.h"
#include "strlist.h"

static int send_incexc_str(const char *pre, const char *str)
{
	char *tosend=NULL;
	if(!(tosend=prepend(pre, str, strlen(str), " = ")))
		return -1;
	if(async_write_str(CMD_GEN, tosend))
	{
		logp("Error in async_write_str when sending incexc\n");
		return -1;
	}
	return 0;
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

int incexc_send_client(struct config *conf, struct cntr *p1cntr)
{
	int ret=-1;
	char cmd='\0';
	char *buf=NULL;
	size_t len=0;
	if(async_write_str(CMD_GEN, "incexc"))
		goto end;
	if(async_read(&cmd, &buf, &len))
		goto end;
	if(cmd==CMD_GEN)
	{
		if(strcmp(buf, "incexc ok"))
		{
			logp("unexpected response to incexc from server: %s\n",
				buf);
			goto end;
		}
	}
	else
	{
		logp("unexpected response to incexc from server: %c:%s\n",
			cmd, buf);
		goto end;
	}
	if(
	    /*  send_incexc_from_strlist("include", "exclude",
		conf->sdcount, conf->startdir)
	  || */ send_incexc_from_strlist("include", "exclude",
		conf->iecount, conf->incexcdir)
	  || send_incexc_from_strlist("cross_filesystem", "cross_filesystem",
		conf->fscount, conf->fschgdir)
	  || send_incexc_from_strlist("nobackup", "nobackup",
		conf->nbcount, conf->nobackup)
	  || send_incexc_from_strlist("exclude_ext", "exclude_ext",
		conf->excount, conf->excext)
	  || send_incexc_from_strlist("exclude_fs", "exclude_fs",
		conf->exfscount, conf->excfs)
	  || send_incexc_from_strlist("read_fifo", "read_fifo",
		conf->ffcount, conf->fifos)
	  || send_incexc_int("cross_all_filesystems",
		conf->cross_all_filesystems)
	  || send_incexc_int("read_all_fifos", conf->read_all_fifos)
	  || send_incexc_long("min_file_size", conf->min_file_size)
	  || send_incexc_long("max_file_size", conf->max_file_size))
		goto end;

	if(async_write_str(CMD_GEN, "incexc end"))
		goto end;
	if(buf) { free(buf); buf=NULL; }
	if(async_read(&cmd, &buf, &len))
		goto end;
	if(cmd==CMD_GEN)
	{
		if(strcmp(buf, "incexc end ok"))
		{
			logp("unexpected response to incexc end from server: %s\n",
				buf);
			goto end;
		}
	}
	else
	{
		logp("unexpected response to incexc end from server: %c:%s\n",
			cmd, buf);
		goto end;
	}
	ret=0; // Everything is OK if we got to here.
end:
	if(buf) free(buf);
	return ret;
}
