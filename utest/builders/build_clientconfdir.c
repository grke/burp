#include "../test.h"
#include "../../src/alloc.h"
#include "../../src/cstat.h"
#include "../../src/fsops.h"

#include "build.h"
#include "build_file.h"

char *get_clientconfdir_path(const char *file)
{
	static char path[256]="";
	snprintf(path, sizeof(path), "%s/%s", CLIENTCONFDIR, file);
	return path;
}

void build_clientconfdir_file(const char *file, const char *content)
{
	const char *path=get_clientconfdir_path(file);
	build_file(path, content);
}

void delete_clientconfdir_file(const char *file)
{
	const char *path=get_clientconfdir_path(file);
	fail_unless(!unlink(path));
}

void build_clientconfdir_files(const char *cnames[], const char *content)
{
	int i=0;
	for(i=0; cnames[i]; i++)
		build_clientconfdir_file(cnames[i], content);
}

void assert_cstat_list(struct cstat *clist, const char *cnames[])
{
	int i;
	struct cstat *c=NULL;
	struct cstat *l=NULL;
	for(i=0, c=clist; cnames && cnames[i]; c=c->next, i++)
	{
		ck_assert_str_eq(cnames[i], c->name);
		l=c;
	}
	fail_unless(c==NULL);
	for(i--, c=l; i>=0; c=c->prev, i--)
		ck_assert_str_eq(cnames[i], c->name);
}
