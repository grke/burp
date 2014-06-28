#include "include.h"

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

int child(struct async *as, struct conf *conf, struct conf *cconf)
{
	int ret=-1;
	int srestore=0;
	int timer_ret=0;
	char *incexc=NULL;
	struct sdirs *sdirs=NULL;

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

	if(!(sdirs=sdirs_alloc())
	  || sdirs_init(sdirs, cconf))
		goto end;

	if(as->asfd->read(as->asfd)) goto end;

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
		ret=run_action_server(as, sdirs,
			incexc, srestore, &timer_ret, cconf);

	if((!ret || cconf->s_script_post_run_on_fail) && cconf->s_script_post)
		ret=run_server_script(as->asfd, "post",
			cconf->s_script_post,
			cconf->s_script_post_arg,
			cconf->s_script_post_notify,
			cconf, ret, timer_ret);

end:
	if(sdirs) lock_release(sdirs->lock);
        sdirs_free(&sdirs);
	return ret;
}
