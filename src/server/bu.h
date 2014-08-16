#ifndef _BU_H
#define _BU_H

#define BU_HARDLINKED	0x0001
#define BU_DELETABLE	0x0002
#define BU_WORKING	0x0004
#define BU_FINISHING	0x0008
#define BU_CURRENT	0x0010
// These are only set on a separate request.
#define BU_MANIFEST	0x0020
#define BU_LOG_BACKUP	0x0040
#define BU_LOG_RESTORE	0x0080
#define BU_LOG_VERIFY	0x0100

// Representing backup directories for a client.

struct bu
{
	char *path;
	char *basename;
	char *data;
	char *delta;
	char *timestamp;
	char *forward_timestamp;
	uint16_t flags;

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
extern int bu_list_get_with_working(struct sdirs *sdirs, struct bu **bu_list);
extern int bu_current_get(struct sdirs *sdirs, struct bu **bu_list);

extern struct bu *bu_alloc(void);
extern void bu_free(struct bu **bu);

#endif
