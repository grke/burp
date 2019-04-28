#include "../test.h"
#include "../../src/alloc.h"
#include "../../src/fsops.h"

#include "build.h"
#include "build_file.h"

void build_file(const char *path, const char *content)
{
	FILE *fp;
	fail_unless(!build_path_w(path));
	fail_unless((fp=fopen(path, "wb"))!=NULL);
	if(content)
		fail_unless(fprintf(fp, "%s", content)==(int)strlen(content));
	fail_unless(!fclose(fp));
}
