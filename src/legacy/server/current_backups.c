#include "include.h"

#include <netdb.h>
#include <librsync.h>
#include <math.h>

/* Need to base librsync block length on the size of the old file, otherwise
   the risk of librsync collisions and silent corruption increases as the
   size of the new file gets bigger. */
size_t get_librsync_block_len(const char *endfile)
{
	size_t ret=0;
	unsigned long long oldlen=0;
	oldlen=strtoull(endfile, NULL, 10);
	ret=(size_t)(ceil(sqrt(oldlen)/16)*16); // round to a multiple of 16.
	if(ret<64) return 64; // minimum of 64 bytes.
	return ret;
}

static char *deleteme_get_path(const char *basedir, struct config *cconf)
{
	static char *deleteme=NULL;
	if(deleteme) { free(deleteme); deleteme=NULL; }
	if(cconf->manual_delete) return cconf->manual_delete;
	return prepend_s(basedir, "deleteme");
}

int deleteme_move(const char *basedir, const char *fullpath, const char *path,
	struct config *cconf)
{
	int ret=-1;
	char *tmp=NULL;
	char *dest=NULL;
	char *deleteme=NULL;
	int attempts=0;
	struct stat statp;
	char suffix[16]="";

	if(!(deleteme=deleteme_get_path(basedir, cconf))
	  || !(tmp=prepend_s(deleteme, path))
	  || mkpath(&tmp, deleteme)
	  || !(dest=prepend("", tmp, strlen(tmp), "")))
		goto end;

	// Try to generate destination paths if the desired one is already
	// taken.
	while(1)
	{
		if(lstat(dest, &statp)) break;
		snprintf(suffix, sizeof(suffix), ".%d", ++attempts);
		if(dest) free(dest);
		if(!(dest=prepend(tmp, suffix, strlen(suffix), "")))
			goto end;
		if(attempts>=10) break; // Give up.
	}

	ret=do_rename(fullpath, dest);

end:
	if(dest) free(dest);
	if(tmp) free(tmp);
	return ret;
}

int deleteme_maybe_delete(struct config *cconf, const char *basedir)
{
	char *deleteme;
	// If manual_delete is on, they will have to delete the files
	// manually, via a cron job or something.
	if(cconf->manual_delete) return 0;
	if(!(deleteme=deleteme_get_path(basedir, cconf))) return -1;
	return recursive_delete(deleteme, NULL, TRUE /* delete all */);
}
