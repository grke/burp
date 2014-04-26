#include "include.h"
#include "../../burp1/client/backup_phase2.h"

// Return 0 for OK, -1 for error, 1 for timer conditions not met.
int do_backup_client(struct async *as, struct conf *conf, enum action action,
	long name_max, int resume)
{
	int ret=0;

	if(action==ACTION_ESTIMATE)
		logp("do estimate client\n");
	else
		logp("do backup client\n");

#if defined(HAVE_WIN32)
	win32_enable_backup_privileges();
#if defined(WIN32_VSS)
	if((ret=win32_start_vss(conf))) return ret;
#endif
	if(action==ACTION_BACKUP_TIMED)
	{
		// Run timed backups with lower priority.
		// I found that this has to be done after the snapshot, or the
		// snapshot never finishes. At least, I waited 30 minutes with
		// nothing happening.
#if defined(B_VSS_XP) || defined(B_VSS_W2K3)
		if(SetThreadPriority(GetCurrentThread(),
					THREAD_PRIORITY_LOWEST))
			logp("Set thread_priority_lowest\n");
		else
			logp("Failed to set thread_priority_lowest\n");
#else
		if(SetThreadPriority(GetCurrentThread(),
					THREAD_MODE_BACKGROUND_BEGIN))
			logp("Set thread_mode_background_begin\n");
		else
			logp("Failed to set thread_mode_background_begin\n");
#endif
	}
#endif

	// Scan the file system and send the results to the server.
	// Skip phase1 if the server wanted to resume.
	if(!ret && !resume)
		ret=backup_phase1_client(as, conf, name_max,
			action==ACTION_ESTIMATE);

	if(action!=ACTION_ESTIMATE && !ret)
	{
		// Now, the server will be telling us what data we need to
		// send.
		if(conf->protocol==PROTO_BURP1)
			ret=backup_phase2_client_burp1(conf, resume);
		else
			ret=backup_phase2_client(as, conf, resume);
	}

	if(action==ACTION_ESTIMATE) cntr_print(conf->cntr, ACTION_ESTIMATE);

#if defined(HAVE_WIN32)
	if(action==ACTION_BACKUP_TIMED)
	{
		if(SetThreadPriority(GetCurrentThread(),
					THREAD_MODE_BACKGROUND_END))
			logp("Set thread_mode_background_end\n");
		else
			logp("Failed to set thread_mode_background_end\n");
	}
#if defined(WIN32_VSS)
	win32_stop_vss();
#endif
#endif

	return ret;
}
