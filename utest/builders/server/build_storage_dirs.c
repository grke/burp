#include "../../test.h"
#include "../../../src/bu.h"
#include "../../../src/fsops.h"
#include "../../../src/server/sdirs.h"
#include "../../../src/server/timestamp.h"
#include "build_storage_dirs.h"

static void create_file(const char *path)
{
	FILE *fp;
	fail_unless((fp=fopen(path, "wb"))!=NULL);
	fail_unless(!fclose(fp));
}

void build_storage_dirs(struct sdirs *sdirs, struct sd *s, int len)
{
	int i=0;
	time_t t=0;
	char backup[128]="";
	char hardlinked[128]="";
	char timestamp_path[128]="";
	for(i=0; i<len; i++)
	{
		snprintf(backup, sizeof(backup),
			"%s/%s", sdirs->client, s[i].timestamp);
		snprintf(timestamp_path, sizeof(timestamp_path),
			"%s/timestamp", backup);
                fail_unless(!build_path_w(backup));
                fail_unless(!mkdir(backup, 0777));
		fail_unless(!timestamp_write(timestamp_path, s[i].timestamp));
		if(s[i].flags & BU_CURRENT)
			fail_unless(!symlink(s[i].timestamp, sdirs->current));
		if(s[i].flags & BU_HARDLINKED)
		{
			snprintf(hardlinked, sizeof(hardlinked),
				"%s/hardlinked", backup);
			create_file(hardlinked);
		}
		t+=60*60*24; // Add one day.
	}
}
