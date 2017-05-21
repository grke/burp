#ifndef _BU_H
#define _BU_H

#define BU_HARDLINKED		0x0001
#define BU_DELETABLE		0x0002
#define BU_WORKING		0x0004
#define BU_FINISHING		0x0008
#define BU_CURRENT		0x0010
#define BU_LIVE_COUNTERS	0x0020 // Only set in json_input.
#define BU_MANIFEST		0x0040
// These are only set on a separate request.
// Careful with the bit shifting in ncurses client with the UP/DOWN keys.
#define BU_LOG_BACKUP		0x0080
#define BU_LOG_RESTORE		0x0100
#define BU_LOG_VERIFY		0x0200
#define BU_STATS_BACKUP		0x0400
#define BU_STATS_RESTORE	0x0800
#define BU_STATS_VERIFY		0x1000

// Representing backup directories on the server for a client.
// Needed on the client side too, as the status monitor stuff uses it.

struct bu
{
	char *path;
	char *basename;
	char *data;
	char *delta;
	char *timestamp;
	uint16_t flags;

	// The number of the backup.
	uint64_t bno;
	// Transposed backup number - will set the oldest backup to 1.
	uint64_t trbno;

	// The position of this item in the array.
	uint64_t index;

	struct bu *next;
	struct bu *prev;
};

extern int bu_init(struct bu *bu, char *fullpath, char *basename,
	char *timestampstr, uint16_t flags);
extern void bu_list_free(struct bu **bu_list);
extern struct bu *bu_alloc(void);
extern void bu_free(struct bu **bu);
extern struct bu *bu_find_current(struct bu *bu);
extern struct bu *bu_find_working_or_finishing(struct bu *bu);

#endif
