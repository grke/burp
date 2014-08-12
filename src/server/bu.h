#ifndef _BU_H
#define _BU_H

#define BU_HARDLINKED	0x01
#define BU_DELETABLE	0x02
#define BU_WORKING	0x04
#define BU_FINISHING	0x10
#define BU_CURRENT	0x20

// Representing backup directories for a client.

struct bu
{
	char *path;
	char *basename;
	char *data;
	char *delta;
	char *timestamp;
	char *forward_timestamp;
	uint8_t flags;

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
