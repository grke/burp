#include "include.h"

static int send_incexc_str(struct async *as, const char *pre, const char *str)
{
	char *tosend=NULL;
	int rc=0;
	if(!str) return 0;
	if(!(tosend=prepend(pre, str, strlen(str), " = ")))
		rc=-1;
	if(!rc && as->write_str(as, CMD_GEN, tosend))
	{
		logp("Error in async_write_str when sending incexc\n");
		rc=-1;
	}
	if(tosend)
		free(tosend);
	return rc;
}

static int send_incexc_int(struct async *as, const char *pre, int myint)
{
	char tmp[64]="";
	snprintf(tmp, sizeof(tmp), "%d", myint);
	return send_incexc_str(as, pre, tmp);
}

static int send_incexc_long(struct async *as, const char *pre, long mylong)
{
	char tmp[32]="";
	snprintf(tmp, sizeof(tmp), "%lu", mylong);
	return send_incexc_str(as, pre, tmp);
}

static int send_incexc_from_strlist(struct async *as,
	const char *prepend_on, const char *prepend_off, struct strlist *list)
{
	struct strlist *l;
	for(l=list; l; l=l->next)
		if(send_incexc_str(as, l->flag?prepend_on:prepend_off, l->path))
			return -1;
	return 0;
}

static int do_sends(struct async *as, struct conf *conf)
{
	if(  send_incexc_from_strlist(as, "include", "exclude",
		conf->incexcdir)
	  || send_incexc_from_strlist(as, "include_glob", "include_glob",
		conf->incglob)
	  || send_incexc_from_strlist(as, "cross_filesystem", "cross_filesystem",
		conf->fschgdir)
	  || send_incexc_from_strlist(as, "nobackup", "nobackup",
		conf->nobackup)
	  || send_incexc_from_strlist(as, "include_ext", "include_ext",
		conf->incext)
	  || send_incexc_from_strlist(as, "exclude_ext", "exclude_ext",
		conf->excext)
	  || send_incexc_from_strlist(as, "include_regex", "include_regex",
		conf->increg)
	  || send_incexc_from_strlist(as, "exclude_regex", "exclude_regex",
		conf->excreg)
	  || send_incexc_from_strlist(as, "exclude_fs", "exclude_fs",
		conf->excfs)
	  || send_incexc_from_strlist(as, "exclude_comp", "exclude_comp",
		conf->excom)
	  || send_incexc_from_strlist(as, "read_fifo", "read_fifo",
		conf->fifos)
	  || send_incexc_from_strlist(as, "read_blockdev", "read_blockdev",
		conf->blockdevs)
	  || send_incexc_int(as, "cross_all_filesystems",
		conf->cross_all_filesystems)
	  || send_incexc_int(as, "read_all_fifos", conf->read_all_fifos)
	  || send_incexc_long(as, "min_file_size", conf->min_file_size)
	  || send_incexc_long(as, "max_file_size", conf->max_file_size)
	  || send_incexc_str(as, "vss_drives", conf->vss_drives))
		return -1;
	return 0;
}

static int do_sends_restore(struct async *as, struct conf *conf)
{
	if(  send_incexc_from_strlist(as, "include", "exclude", conf->incexcdir)
	  || send_incexc_str(as, "orig_client", conf->orig_client)
	  || send_incexc_str(as, "backup", conf->backup)
	  || send_incexc_str(as, "restoreprefix", conf->restoreprefix)
	  || send_incexc_str(as, "regex", conf->regex)
	  || send_incexc_int(as, "overwrite", conf->overwrite)
	  || send_incexc_long(as, "strip", conf->strip))
		return -1;
	return 0;
}

static int do_request_response(struct async *as,
	const char *reqstr, const char *repstr)
{
	return (as->write_str(as, CMD_GEN, reqstr)
	  || as->read_expect(as, CMD_GEN, repstr));
}

int incexc_send_client(struct async *as, struct conf *conf)
{
	if(do_request_response(as, "incexc", "incexc ok")
	  || do_sends(as, conf)
	  || do_request_response(as, "incexc end", "incexc end ok"))
		return -1;
	return 0;
}

int incexc_send_server(struct async *as, struct conf *conf)
{
	/* 'sincexc' and 'sincexc ok' have already been exchanged,
	   so go straight into doing the sends. */
	if(do_sends(as, conf)
	  || do_request_response(as, "sincexc end", "sincexc end ok"))
		return -1;
	return 0;
}

int incexc_send_server_restore(struct async *as, struct conf *conf)
{
	/* 'srestore' and 'srestore ok' have already been exchanged,
	   so go straight into doing the sends. */
	if(do_sends_restore(as, conf)
	  || do_request_response(as, "srestore end", "srestore end ok"))
		return -1;
	return 0;
}
