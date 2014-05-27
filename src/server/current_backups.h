#ifndef _CURRENT_BACKUPS_H
#define _CURRENT_BACKUPS_H

// FIX THIS: Turn this into a double-linked list and get rid of the stupid
// array.
struct bu
{
	char *path;
	char *basename;
	char *data;
	char *delta;
	char *timestamp;
	char *forward_timestamp;
	int hardlinked;
	int deletable;

	// The number of the backup.
	unsigned long bno;
	// Transposed backup number - will set the oldest backup to 1.
	unsigned long trbno;

	// The position of this item in the array.
	unsigned long index;
};

extern void free_current_backups(struct bu **arr, int a);
extern int get_current_backups(struct asfd *asfd, struct sdirs *sdirs,
	struct bu **arr, int *a, int log);
extern int get_current_backups_str(struct asfd *asfd, const char *dir,
	struct bu **arr, int *a, int log);

#endif
