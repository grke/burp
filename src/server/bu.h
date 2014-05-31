#ifndef _BU_H
#define _BU_H

// Current backups.

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

	struct bu *next;
	struct bu *prev;
};

extern void bu_free(struct bu **arr, int a);
extern int bu_get(struct asfd *asfd, struct sdirs *sdirs,
	struct bu **arr, int *a, int log);
extern int bu_get_str(struct asfd *asfd, const char *dir,
	struct bu **arr, int *a, int log);

#endif
