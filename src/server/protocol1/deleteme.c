#include "include.h"

static char *deleteme_get_path(const char *basedir, struct conf **cconfs)
{
	static char *deleteme=NULL;
	char *manual_delete=get_string(cconfs[OPT_MANUAL_DELETE]);
	free_w(&deleteme);
	if(manual_delete) return manual_delete;
	return prepend_s(basedir, "deleteme");
}

int deleteme_move(const char *basedir, const char *fullpath, const char *path,
	struct conf **cconfs)
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

	if(!(deleteme=deleteme_get_path(basedir, cconfs))
	  || !(tmp=prepend_s(deleteme, path))
	  || mkpath(&tmp, deleteme)
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
		if(attempts>=10) break; // Give up.
	}

	// Possible race condition is of no consequence, as the destination
	// will need to be deleted at some point anyway.
	ret=do_rename(fullpath, dest);

end:
	free_w(&dest);
	free_w(&tmp);
	return ret;
}

int deleteme_maybe_delete(struct conf **cconfs, const char *basedir)
{
	char *deleteme;
	// If manual_delete is on, they will have to delete the files
	// manually, via a cron job or something.
	if(get_string(cconfs[OPT_MANUAL_DELETE])) return 0;
	if(!(deleteme=deleteme_get_path(basedir, cconfs))) return -1;
	return recursive_delete(deleteme, NULL, 1 /* delete all */);
}
