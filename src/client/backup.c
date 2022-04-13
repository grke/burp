#include "../burp.h"
#include "../action.h"
#include "../asfd.h"
#include "../async.h"
#include "../cntr.h"
#include "../conf.h"
#include "../handy.h"
#include "../log.h"
#include "backup_phase1.h"
#include "cvss.h"
#include "protocol1/backup_phase2.h"
#include "backup.h"

#ifdef HAVE_WIN32
static void set_priority(int priority, const char *str)
{
	if(SetThreadPriority(GetCurrentThread(), priority))
		logp("Set %s\n", str);
	else
		logp("Failed to set %s\n", str);
}

static void set_low_priority(void)
{
	// Run timed backups with lower priority. I found that this has to be
	// done after the snapshot, or the snapshot never finishes. At least, I
	// waited 30 minutes with nothing happening.
#if defined(B_VSS_XP) || defined(B_VSS_W2K3)
	set_priority(THREAD_PRIORITY_LOWEST,
		"thread_priority_lowest");
#else
	set_priority(THREAD_MODE_BACKGROUND_BEGIN,
		"thread_mode_background_begin");
#endif
}

static void unset_low_priority(void)
{
	set_priority(THREAD_MODE_BACKGROUND_END,
		"thread_mode_background_end");
}
#endif

// Return 0 for OK, -1 for error.
int do_backup_client(struct asfd *asfd, struct conf **confs, enum action action,
	int resume)
{
	int ret=-1;
	int breaking=get_int(confs[OPT_BREAKPOINT]);

	if(action==ACTION_ESTIMATE)
		logp("do estimate client\n");
	else
	{
		logp("do backup client\n");
		logp("Using librsync hash %s\n",
			rshash_to_str(get_e_rshash(confs[OPT_RSHASH])));
	}

#ifdef HAVE_WIN32
	win32_enable_backup_privileges();
#ifdef WIN32_VSS
	if(win32_start_vss(asfd, confs))
	{
		log_and_send(asfd, "Problem with VSS\n");
		return ret;
	}
#endif
	if(action==ACTION_BACKUP_TIMED) set_low_priority();
#endif

	// Scan the file system and send the results to the server.
	// Skip phase1 if the server wanted to resume.
	if(!resume)
	{
		if(breaking==1)
		{
			breakpoint(breaking, __func__);
			goto end;
		}
		if(backup_phase1_client(asfd, confs))
			goto end;
	}

	switch(action)
	{
		case ACTION_DIFF:
		case ACTION_DIFF_LONG:
			ret=1;
			goto end;
		case ACTION_ESTIMATE:
			cntr_print(get_cntr(confs), ACTION_ESTIMATE);
			break;
		default:
			// Now, the server will be telling us what data we need
			// to send.
			if(breaking==2)
			{
				breakpoint(breaking, __func__);
				goto end;
			}

			ret=backup_phase2_client_protocol1(asfd,
				confs, resume);
			if(ret) goto end;
			break;
	}

	ret=0;
end:
#if defined(HAVE_WIN32)
	if(action==ACTION_BACKUP_TIMED) unset_low_priority();
#if defined(WIN32_VSS)
	win32_stop_vss();
#endif
#endif
	return ret;
}
