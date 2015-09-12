#include "../../test.h"
#include "../../../src/bu.h"
#include "../../../src/fsops.h"
#include "../../../src/server/sdirs.h"
#include "../../../src/server/timestamp.h"
#include "build_storage_dirs.h"

static void create_file(const char *backup,
	const char *file, int compressed_logs)
{
	FILE *fp;
	char path[258]="";
	if(compressed_logs)
		snprintf(path, sizeof(path), "%s/%s.gz", backup, file);
	else
		snprintf(path, sizeof(path), "%s/%s", backup, file);
	fail_unless((fp=fopen(path, "wb"))!=NULL);
	fail_unless(!fclose(fp));
}

static void do_build_storage_dirs(struct sdirs *sdirs, struct sd *s, int len,
	int compressed_logs)
{
	int i=0;
	time_t t=0;
	char backup[128]="";
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
		if(s[i].flags & BU_WORKING)
			fail_unless(!symlink(s[i].timestamp, sdirs->working));
		if(s[i].flags & BU_FINISHING)
			fail_unless(!symlink(s[i].timestamp, sdirs->finishing));

		if(s[i].flags & BU_MANIFEST)
			create_file(backup, "manifest", compressed_logs);
		if(s[i].flags & BU_LOG_BACKUP)
			create_file(backup, "log", compressed_logs);
		if(s[i].flags & BU_LOG_RESTORE)
			create_file(backup, "restorelog", compressed_logs);
		if(s[i].flags & BU_LOG_VERIFY)
			create_file(backup, "verifylog", compressed_logs);
		// This one is never compressed.
		if(s[i].flags & BU_HARDLINKED)
			create_file(backup, "hardlinked", 0);

		t+=60*60*24; // Add one day.
	}
}

void build_storage_dirs(struct sdirs *sdirs, struct sd *s, int len)
{
	do_build_storage_dirs(sdirs, s, len, 0 /* compressed_logs */);
}

void build_storage_dirs_compressed_logs(struct sdirs *sdirs,
	struct sd *s, int len)
{
	do_build_storage_dirs(sdirs, s, len, 1 /* compressed_logs */);
}
