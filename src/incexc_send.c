#include "include.h"

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

static int send_incexc_from_strlist(const char *prepend_on, const char *prepend_off, struct strlist *list)
{
	struct strlist *l;
	for(l=list; l; l=l->next)
		if(send_incexc_str(l->flag?prepend_on:prepend_off, l->path))
			return -1;
	return 0;
}

static int do_sends(struct config *conf)
{
	if(  send_incexc_from_strlist("include", "exclude",
		conf->incexcdir)
	  || send_incexc_from_strlist("include_glob", "include_glob",
		conf->incglob)
	  || send_incexc_from_strlist("cross_filesystem", "cross_filesystem",
		conf->fschgdir)
	  || send_incexc_from_strlist("nobackup", "nobackup",
		conf->nobackup)
	  || send_incexc_from_strlist("include_ext", "include_ext",
		conf->incext)
	  || send_incexc_from_strlist("exclude_ext", "exclude_ext",
		conf->excext)
	  || send_incexc_from_strlist("include_regex", "include_regex",
		conf->increg)
	  || send_incexc_from_strlist("exclude_regex", "exclude_regex",
		conf->excreg)
	  || send_incexc_from_strlist("exclude_fs", "exclude_fs",
		conf->excfs)
	  || send_incexc_from_strlist("exclude_comp", "exclude_comp",
		conf->excom)
	  || send_incexc_from_strlist("read_fifo", "read_fifo",
		conf->fifos)
	  || send_incexc_from_strlist("read_blockdev", "read_blockdev",
		conf->blockdevs)
	  || send_incexc_int("cross_all_filesystems",
		conf->cross_all_filesystems)
	  || send_incexc_int("read_all_fifos", conf->read_all_fifos)
	  || send_incexc_long("min_file_size", conf->min_file_size)
	  || send_incexc_long("max_file_size", conf->max_file_size)
	  || send_incexc_str("vss_drives", conf->vss_drives))
		return -1;
	return 0;
}

static int do_sends_restore(struct config *conf)
{
	if(  send_incexc_from_strlist("include", "exclude", conf->incexcdir)
	  || send_incexc_str("orig_client", conf->orig_client)
	  || send_incexc_str("backup", conf->backup)
	  || send_incexc_str("restoreprefix", conf->restoreprefix)
	  || send_incexc_str("regex", conf->regex)
	  || send_incexc_int("overwrite", conf->overwrite)
	  || send_incexc_long("strip", conf->strip))
		return -1;
	return 0;
}

static int do_request_response(const char *reqstr, const char *repstr)
{
	return (async_write_str(CMD_GEN, reqstr)
	  || async_read_expect(CMD_GEN, repstr));
}

int incexc_send_client(struct config *conf)
{
	if(do_request_response("incexc", "incexc ok")
	  || do_sends(conf)
	  || do_request_response("incexc end", "incexc end ok"))
		return -1;
	return 0;
}

int incexc_send_server(struct config *conf)
{
	/* 'sincexc' and 'sincexc ok' have already been exchanged,
	   so go straight into doing the sends. */
	if(do_sends(conf)
	  || do_request_response("sincexc end", "sincexc end ok"))
		return -1;
	return 0;
}

int incexc_send_server_restore(struct config *conf)
{
	/* 'srestore' and 'srestore ok' have already been exchanged,
	   so go straight into doing the sends. */
	if(do_sends_restore(conf)
	  || do_request_response("srestore end", "srestore end ok"))
		return -1;
	return 0;
}
