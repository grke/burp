#ifndef _BU_H
#define _BU_H

// Current backups.

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

extern void bu_list_free(struct bu **bu_list);
extern int bu_list_get(struct sdirs *sdirs, struct bu **bu_list);
extern int bu_current_get(struct sdirs *sdirs, struct bu **bu_list);

extern struct bu *bu_alloc(void);
extern int bu_init(struct bu *bu, char *fullpath, char *basename,
        char *timestampstr, int hardlinked);
extern void bu_free(struct bu **bu);


#endif
