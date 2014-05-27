#ifndef _CURRENT_BACKUPS_H
#define _CURRENT_BACKUPS_H

struct bu
{
	char *path;
	char *basename;
	char *data;
	char *delta;
	char *timestamp;
	char *forward_timestamp;
	unsigned long index;
	int hardlinked;
	int deletable;
	// transposed index - will set the oldest backup to 1.
	unsigned long trindex;
};

extern void free_current_backups(struct bu **arr, int a);
extern int get_current_backups(struct asfd *asfd, struct sdirs *sdirs,
	struct bu **arr, int *a, int log);
extern int get_current_backups_str(struct asfd *asfd, const char *dir,
	struct bu **arr, int *a, int log);
extern int remove_old_backups(struct asfd *asfd,
	struct sdirs *sdirs, struct conf *cconf);
extern int delete_backup(struct sdirs *sdirs, struct conf *cconf,
	struct bu *arr, int a, int b);

#endif
