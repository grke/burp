#ifndef _CURRENT_BACKUPS_H
#define _CURRENT_BACKUPS_H

struct bu
{
	char *path;
	char *data;
	char *delta;
	char *timestamp;
	char *forward_timestamp;
	unsigned long index;
	unsigned long forward_index;
	int hardlinked;
	int deletable;
	// transposed index - will set the oldest backup to 1.
	unsigned long trindex;
};

extern int recursive_hardlink(const char *src, const char *dst, const char *client, struct cntr *p1cntr, struct cntr *cntr);
extern int recursive_delete(const char *d, const char *file, bool delfiles);
extern void free_current_backups(struct bu **arr, int a);
extern int get_current_backups(const char *basedir, struct bu **arr, int *a, int log);
extern int get_new_timestamp(const char *basedir, char *buf, size_t s);
extern int read_timestamp(const char *path, char buf[], size_t len);
extern int write_timestamp(const char *timestamp, const char *tstmp);
extern int compress_file(const char *current, const char *file, struct config *cconf);
extern int compress_filename(const char *d, const char *file, const char *zfile, struct config *cconf);
extern int remove_old_backups(const char *basedir, struct config *cconf, const char *client);
extern int compile_regex(regex_t **regex, const char *str);
extern int check_regex(regex_t *regex, const char *buf);
extern size_t get_librsync_block_len(const char *endfile);


#endif // _CURRENT_BACKUPS_H
