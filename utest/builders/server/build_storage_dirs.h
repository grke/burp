#ifndef _BUILDER_STORAGE_DIRS
#define _BUILDER_STORAGE_DIRS

struct sdirs;

struct sd
{
        const char *timestamp;
        unsigned long bno;
        unsigned long index;
        uint16_t flags;
};

extern void build_storage_dirs(struct sdirs *sdirs, struct sd *s, int len);
extern void build_storage_dirs_compressed_logs(struct sdirs *sdirs,
	struct sd *s, int len);

#endif
