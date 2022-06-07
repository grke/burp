#include "../burp.h"
#include "../alloc.h"
#include "../conf.h"
#include "../fsops.h"
#include "../prepend.h"
#include "sdirs.h"
#include "deleteme.h"

int deleteme_move(struct sdirs *sdirs, const char *fullpath, const char *path)
{
	int ret=-1;
	char *tmp=NULL;
	char *dest=NULL;
	int attempts=0;
	struct stat statp;
	char suffix[16]="";
	char *timestamp=NULL;

	if(lstat(fullpath, &statp) && errno==ENOENT)
	{
		// The path to move aside does not exist.
		// Treat this as OK.
		ret=0;
		goto end;
	}

	if(!(tmp=prepend_s(sdirs->deleteme, path))
	  || mkpath(&tmp, sdirs->deleteme)
	  || !(dest=prepend("", tmp)))
		goto end;

	// Try to generate destination paths if the desired one is already
	// taken.
	while(1)
	{
		if(lstat(dest, &statp)) break;
		snprintf(suffix, sizeof(suffix), ".%d", ++attempts);
		free_w(&dest);
		if(!(dest=prepend(tmp, suffix)))
			goto end;
		if(attempts>=100) break; // Give up.
	}

	// Paranoia - really do not want the deleteme directory to be loaded
	// as if it were a normal storage directory, so remove the timestamp.
	if(!(timestamp=prepend_s(fullpath, "timestamp")))
		goto end;
	unlink(timestamp);

	// Possible race condition is of no consequence, as the destination
	// will need to be deleted at some point anyway.
	ret=do_rename(fullpath, dest);

end:
	free_w(&dest);
	free_w(&tmp);
	free_w(&timestamp);
	return ret;
}

int deleteme_maybe_delete(struct conf **cconfs, struct sdirs *sdirs)
{
	// If manual_delete is on, they will have to delete the files
	// manually, via a cron job or something.
	if(get_string(cconfs[OPT_MANUAL_DELETE])) return 0;
	return recursive_delete(sdirs->deleteme);
}
