#include "include.h"
#include "../cmd.h"

static struct asfd *wasfd=NULL;

int write_status(enum cntr_status cntr_status,
	const char *path, struct conf **confs)
{
	time_t now=0;
	time_t diff=0;
	static time_t lasttime=0;
	static size_t l=0;
	static struct iobuf *wbuf=NULL;

	if(!wasfd) return 0;

	// Only update every 2 seconds.
	now=time(NULL);
	diff=now-lasttime;
	if(diff<2)
	{
		// Might as well do this in case they fiddled their
		// clock back in time.
		if(diff<0) lasttime=now;
		return 0;
	}
	lasttime=now;

	// Only get a new string if we did not manage to write the previous
	// one.
	if(!l)
	{
		get_cntr(confs[OPT_CNTR])->cntr_status=cntr_status;
		if(!(l=cntr_to_str(get_cntr(confs[OPT_CNTR]), path))) goto error;
		if(!wbuf && !(wbuf=iobuf_alloc())) goto error;
		iobuf_set(wbuf, CMD_APPEND, get_cntr(confs[OPT_CNTR])->str, l);
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

static int run_server_script(struct asfd *asfd,
	const char *pre_or_post,
	const char *script, struct strlist *script_arg,
	uint8_t notify, struct conf *cconf, int backup_ret, int timer_ret)
{
	int a=0;
	int ret=0;
	char *logbuf=NULL;
	const char *args[12];
	struct iobuf *rbuf=asfd->rbuf;

	args[a++]=script;
	args[a++]=pre_or_post;
	args[a++]=rbuf->buf?rbuf->buf:"", // Action requested by client.
	args[a++]=cconf->cname;
	args[a++]=backup_ret?"1":"0", // Indicate success or failure.
	// Indicate whether the timer script said OK or not.
	args[a++]=timer_ret?"1":"0",
	args[a++]=NULL;

	// Do not have a client storage directory, so capture the
	// output in a buffer to pass to the notification script.
	if(run_script_to_buf(asfd, args, script_arg, cconf, 1, 1, 0, &logbuf))
	{
		char msg[256];
		snprintf(msg, sizeof(msg),
			"server %s script %s returned an error",
			pre_or_post, script);
		log_and_send(asfd, msg);
		ret=-1;
		if(!notify) goto end;

		a=0;
		args[a++]=cconf->n_failure_script;
		args[a++]=cconf->cname;
		// magic - set basedir blank and the
		// notify script will know to get the content
		// from the next argument (usually storagedir)
		args[a++]=""; // usually basedir
		args[a++]=logbuf?logbuf:""; //usually storagedir
		args[a++]=""; // usually file
		args[a++]=""; // usually brv
		args[a++]=""; // usually warnings
		args[a++]=NULL;
		run_script(asfd, args, cconf->n_failure_arg, cconf, 1, 1, 0);
	}
end:
	if(logbuf) free(logbuf);
	return ret;
}

int child(struct async *as,
	int status_wfd, struct conf **confs, struct conf *cconf)
{
	int ret=-1;
	int srestore=0;
	int timer_ret=0;
	char *incexc=NULL;
	struct asfd *asfd;

	// If we are not a status server, we are a normal child - set up the
	// parent socket to write status to.
	if(status_wfd>0
	  && !(wasfd=setup_asfd(as, "child status pipe", &status_wfd, NULL,
		ASFD_STREAM_STANDARD, ASFD_FD_CHILD_PIPE_WRITE, -1, cconf)))
			goto end;

	/* Has to be before the chuser/chgrp stuff to allow clients to switch
	   to different clients when both clients have different user/group
	   settings. */
	if(extra_comms(as, &incexc, &srestore, conf, cconf))
	{
		log_and_send(as->asfd, "running extra comms failed on server");
		goto end;
	}

	/* Now that the client conf is loaded, we might want to chuser or
	   chgrp.
	   The main process could have already done this, so we don't want
	   to try doing it again if cconf has the same values, because it
	   will fail. */
	if( (!conf->user  || (cconf->user && strcmp(conf->user, cconf->user)))
	  ||(!conf->group ||(cconf->group && strcmp(conf->group,cconf->group))))
	{
		if(chuser_and_or_chgrp(cconf))
		{
			log_and_send(as->asfd,
				"chuser_and_or_chgrp failed on server");
			goto end;
		}
	}

	if(as->asfd->read(as->asfd)) goto end;

	// If this is a status server, run the status server.
	for(asfd=as->asfd; asfd; asfd=asfd->next)
	{
		if(asfd->fdtype!=ASFD_FD_CHILD_PIPE_READ) continue;
		ret=status_server(as, cconf);
		goto end;
	}

	ret=0;

	// FIX THIS: Make the script components part of a struct, and just
	// pass in the correct struct. Same below.
	if(cconf->s_script_pre)
		ret=run_server_script(as->asfd, "pre",
			cconf->s_script_pre,
			cconf->s_script_pre_arg,
			cconf->s_script_pre_notify,
			cconf, ret, timer_ret);

	if(!ret)
		ret=run_action_server(as, incexc, srestore, &timer_ret, cconf);

	if((!ret || cconf->s_script_post_run_on_fail) && cconf->s_script_post)
		ret=run_server_script(as->asfd, "post",
			cconf->s_script_post,
			cconf->s_script_post_arg,
			cconf->s_script_post_notify,
			cconf, ret, timer_ret);

end:
	return ret;
}
