#include "../burp.h"
#include "../alloc.h"
#include "../asfd.h"
#include "../async.h"
#include "../cmd.h"
#include "../cntr.h"
#include "../conf.h"
#include "../cstat.h"
#include "../handy.h"
#include "../iobuf.h"
#include "../log.h"
#include "../prepend.h"
#include "../run_script.h"
#include "extra_comms.h"
#include "monitor/status_server.h"
#include "run_action.h"
#include "child.h"
#include "timer.h"

static struct asfd *wasfd=NULL;

static enum action act=ACTION_UNSET;

static int write_status(
	enum cntr_status cntr_status,
	const char *path,
	struct cntr *cntr,
	time_t now
) {
	static size_t l=0;
	static struct iobuf *wbuf=NULL;
	static time_t lasttime=0;
	time_t diff=0;

	// Only update every 2 seconds.
	diff=now-lasttime;
	if(diff<2)
	{
		// Might as well do this in case they fiddled their
		// clock back in time.
		if(diff<0) lasttime=now;
		return 0;
	}
	lasttime=now;

	if(!wasfd) return 0;
	if(!cntr || !cntr->bno)
		return 0;

	// Only get a new string if we did not manage to write the previous
	// one.
	if(!l)
	{
		cntr->cntr_status=cntr_status;
		if(!(l=cntr_to_str(cntr, path))) goto error;
		if(!wbuf && !(wbuf=iobuf_alloc())) goto error;
		iobuf_set(wbuf, CMD_APPEND, cntr->str, l);
	}

	switch(wasfd->append_all_to_write_buffer(wasfd, wbuf))
	{
		case APPEND_OK:
			l=0; // Fall through.
		case APPEND_BLOCKED:
			return 0;
		default:
			break;
	}
error:
	iobuf_free(&wbuf);
	return -1;
}

static int check_timer_script(
	enum cntr_status cntr_status,
	struct asfd *asfd,
	struct sdirs *sdirs,
	struct conf **confs,
	time_t now
) {
	int interval;
	time_t diff=0;
	static time_t lasttime=0;

	if(cntr_status!=CNTR_STATUS_SCANNING
	&& cntr_status!=CNTR_STATUS_BACKUP)
		return 0;

	// The conf is in minutes, so multiply by 60 to get seconds.
	interval=get_int(confs[OPT_TIMER_REPEAT_INTERVAL]) * 60;
	if (!interval)
		return 0;

	diff=now-lasttime;
	if(diff<interval)
	{
		// Might as well do this in case they fiddled their
		// clock back in time.
		if(diff<0) lasttime=now;
		return 0;
	}
	lasttime=now;

	return run_timer(
		asfd,
		sdirs,
		confs
	);
}

int timed_operation(
	enum cntr_status cntr_status,
	const char *path,
	struct asfd *asfd,
	struct sdirs *sdirs,
	struct conf **confs
) {
	time_t now=0;

	if(!confs) return 0;

	now=time(NULL);

	if(write_status(cntr_status, path, get_cntr(confs), now))
		return -1;

	if(act!=ACTION_BACKUP_TIMED)
		return 0;
	return check_timer_script(cntr_status,
		asfd, sdirs, confs, now);
}

int timed_operation_status_only(
	enum cntr_status cntr_status,
	const char *path,
	struct conf **confs
) {
	return timed_operation(
		cntr_status,
		path,
		NULL, /*asfd*/
		NULL, /*sdirs*/
		confs
	);
}

static int run_server_script(struct asfd *asfd,
	const char *pre_or_post,
	const char *action_from_client,
	const char *script, struct strlist *script_arg,
	uint8_t notify, struct conf **cconfs, int backup_ret, int timer_ret)
{
	int a=0;
	int ret=0;
	char *logbuf=NULL;
	const char *args[12];
	const char *cname=get_string(cconfs[OPT_CNAME]);

	args[a++]=script;
	args[a++]=pre_or_post;
	args[a++]=action_from_client;
	args[a++]=cname;
	args[a++]=backup_ret?"1":"0", // Indicate success or failure.
	// Indicate whether the timer script said OK or not.
	args[a++]=timer_ret?"1":"0",
	args[a++]=NULL;

	// Do not have a client storage directory, so capture the
	// output in a buffer to pass to the notification script.
	if(run_script_to_buf(asfd, args, script_arg, cconfs, 1, 1, 0, &logbuf))
	{
		char msg[256];
		snprintf(msg, sizeof(msg),
			"server %s script %s returned an error",
			pre_or_post, script);
		log_and_send(asfd, msg);
		ret=-1;
		if(!notify) goto end;

		// If this is a backup failure and the client has more servers
		// to failover to, do not notify.
		if(!strncmp_w(action_from_client, "backup")
		  && get_int(cconfs[OPT_N_FAILURE_BACKUP_FAILOVERS_LEFT])
		  && get_int(cconfs[OPT_BACKUP_FAILOVERS_LEFT]))
			goto end;

		a=0;
		args[a++]=get_string(cconfs[OPT_N_FAILURE_SCRIPT]);
		args[a++]=cname;
		// magic - set basedir blank and the
		// notify script will know to get the content
		// from the next argument (usually storagedir)
		args[a++]=""; // usually basedir
		args[a++]=logbuf?logbuf:""; //usually storagedir
		args[a++]=""; // usually file
		args[a++]=""; // usually brv
		args[a++]=""; // usually warnings
		args[a++]=NULL;
		run_script(asfd, args, get_strlist(cconfs[OPT_N_FAILURE_ARG]),
			cconfs, 1, 1, 0);
	}
end:
	free_w(&logbuf);
	return ret;
}

static char *get_action_from_client(const char *buf)
{
	char *cp=NULL;
	char *ret=NULL;

	if(buf)
	{
		if(!strcmp(buf, "backupphase1"))
		{
			act=ACTION_BACKUP;
			return strdup_w("backup", __func__);
		}
		if(!strcmp(buf, "backupphase1timed"))
		{
			act=ACTION_BACKUP_TIMED;
			return strdup_w("backup_timed", __func__);
		}
	}

	if(!(ret=strdup_w(buf?buf:"", __func__)))
		return NULL;
	if((cp=strchr(ret, ' ')))
		*cp='\0';
	return ret;
}

int child(struct async *as, int is_status_server,
	int status_wfd, struct conf **confs, struct conf **cconfs)
{
	int ret=-1;
	int srestore=0;
	int timer_ret=0;
	char *incexc=NULL;
	char *action_from_client=NULL;
	const char *confs_user;
	const char *cconfs_user;
	const char *confs_group;
	const char *cconfs_group;
	const char *s_script_pre;
	const char *s_script_post;

	// If we are not a status server, we are a normal child - set up the
	// parent socket to write status to.
	if(status_wfd>0)
	{
		if(!(wasfd=setup_asfd(as, "child status pipe", &status_wfd,
			/*listen*/"")))
				goto end;
		wasfd->attempt_reads=0;
	}
	/* Has to be before the chuser/chgrp stuff to allow clients to switch
	   to different clients when both clients have different user/group
	   settings. */
	if(extra_comms(as, &incexc, &srestore, confs, cconfs))
	{
		log_and_send(as->asfd, "running extra comms failed on server");
		goto end;
	}

	// Needs to happen after extra_comms, in case extra_comms resets them.
	confs_user=get_string(confs[OPT_USER]);
	cconfs_user=get_string(cconfs[OPT_USER]);
	confs_group=get_string(confs[OPT_GROUP]);
	cconfs_group=get_string(cconfs[OPT_GROUP]);

	/* Now that the client conf is loaded, we might want to chuser or
	   chgrp.
	   The main process could have already done this, so we don't want
	   to try doing it again if cconfs has the same values, because it
	   will fail. */
	if( (!confs_user  || (cconfs_user && strcmp(confs_user, cconfs_user)))
	  ||(!confs_group ||(cconfs_group && strcmp(confs_group,cconfs_group))))
	{
		if(chuser_and_or_chgrp(cconfs_user, cconfs_group, 0))
		{
			log_and_send(as->asfd,
				"chuser_and_or_chgrp failed on server");
			goto end;
		}
	}

	if(as->asfd->read(as->asfd))
		goto end;

	// If this is a status server, run the status server.
	if(is_status_server)
	{
		ret=status_server(as, cconfs);
		goto end;
	}

	if(!(action_from_client=get_action_from_client(as->asfd->rbuf->buf)))
		goto end;
	ret=0;

	s_script_pre=get_string(cconfs[OPT_S_SCRIPT_PRE]);
	s_script_post=get_string(cconfs[OPT_S_SCRIPT_POST]);

	// FIX THIS: Make the script components part of a struct, and just
	// pass in the correct struct. Same below.
	
	if(s_script_pre)
		ret=run_server_script(as->asfd, "pre", action_from_client,
			s_script_pre,
			get_strlist(cconfs[OPT_S_SCRIPT_PRE_ARG]),
			get_int(cconfs[OPT_S_SCRIPT_PRE_NOTIFY]),
			cconfs, ret, timer_ret);

	if(!ret)
		ret=run_action_server(as, incexc, srestore, &timer_ret, cconfs);

	if(!s_script_post)
		goto end;
	if(ret && !get_int(cconfs[OPT_S_SCRIPT_POST_RUN_ON_FAIL]))
			goto end;
	ret=run_server_script(as->asfd, "post", action_from_client,
		s_script_post,
		get_strlist(cconfs[OPT_S_SCRIPT_POST_ARG]),
		get_int(cconfs[OPT_S_SCRIPT_POST_NOTIFY]),
		cconfs, ret, timer_ret);

end:
	free_w(&action_from_client);
	return ret;
}
