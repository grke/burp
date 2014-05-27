#include "include.h"

static char *deleteme_get_path(const char *basedir, struct conf *cconf)
{
	static char *deleteme=NULL;
	if(deleteme) { free(deleteme); deleteme=NULL; }
	if(cconf->manual_delete) return cconf->manual_delete;
	return prepend_s(basedir, "deleteme");
}

int deleteme_move(const char *basedir, const char *fullpath, const char *path,
	struct conf *cconf)
{
	int ret=-1;
	char *tmp=NULL;
	char *dest=NULL;
	char *deleteme=NULL;
	int attempts=0;
	struct stat statp;
	char suffix[16]="";

	if(lstat(fullpath, &statp) && errno==ENOENT)
	{
		// The path to move aside does not exist.
		// Treat this as OK.
		ret=0;
		goto end;
	}

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

	// Possible race condition is of no consequence, as the destination
	// will need to be deleted at some point anyway.
	ret=do_rename(fullpath, dest);

end:
	if(dest) free(dest);
	if(tmp) free(tmp);
	return ret;
}

int deleteme_maybe_delete(struct conf *cconf, const char *basedir)
{
	char *deleteme;
	// If manual_delete is on, they will have to delete the files
	// manually, via a cron job or something.
	if(cconf->manual_delete) return 0;
	if(!(deleteme=deleteme_get_path(basedir, cconf))) return -1;
	return recursive_delete(deleteme, NULL, 1 /* delete all */);
}
