#include "include.h"
#include "burp1/backup_phase2.h"
#include "burp2/backup_phase2.h"

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

// Return 0 for OK, -1 for error, 1 for timer conditions not met.
int do_backup_client(struct asfd *asfd, struct conf *conf, enum action action,
	int resume)
{
	int ret=0;

	if(action==ACTION_ESTIMATE)
		logp("do estimate client\n");
	else
		logp("do backup client\n");

#ifdef HAVE_WIN32
	win32_enable_backup_privileges();
#ifdef WIN32_VSS
	if((ret=win32_start_vss(conf))) return ret;
#endif
	if(action==ACTION_BACKUP_TIMED) set_low_priority();
#endif

	// Scan the file system and send the results to the server.
	// Skip phase1 if the server wanted to resume.
	if(!resume)
		ret=backup_phase1_client(asfd, conf, action==ACTION_ESTIMATE);

	if(!ret) switch(action)
	{
		case ACTION_DIFF:
		case ACTION_DIFF_LONG:
			ret=1;
			break;
		case ACTION_ESTIMATE:
			cntr_print(conf->cntr, ACTION_ESTIMATE);
			break;
		default:
			// Now, the server will be telling us what data we need
			// to send.
			if(conf->protocol==PROTO_BURP1)
				ret=backup_phase2_client_burp1(asfd,
					conf, resume);
			else
				ret=backup_phase2_client_burp2(asfd,
					conf, resume);
			break;
	}

#if defined(HAVE_WIN32)
	if(action==ACTION_BACKUP_TIMED) unset_low_priority();
#if defined(WIN32_VSS)
	win32_stop_vss();
#endif
#endif

	return ret;
}
