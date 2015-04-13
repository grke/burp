#ifndef __DPTH_H
#define __DPTH_H

// Most of the content of these structs are internal to dpth.c.
// Should maybe make them local variables.

// Wrapper around the lock stuff, so that we can have a list of them and
// also keep the save_path without the leading directories.
struct dpth_lock
{
	char save_path[15];
	struct lock *lock;
	struct dpth_lock *next;
};

struct dpth
{
	char *base_path;
	uint16_t prim;
	uint16_t seco;
	uint16_t tert;
	uint16_t sig;
	// Whether we need to lock another data file.
	uint8_t need_data_lock;
	// Currently open data file. Only one is open at a time, while many
	// may be locked.
	FILE *fp;
	// List of locked data files. 
	struct dpth_lock *head;
	struct dpth_lock *tail;
};

extern struct dpth *dpth_alloc(const char *base_path);
extern int dpth_init(struct dpth *dpth);
extern void dpth_free(struct dpth **dpth);

extern int dpth_incr_sig(struct dpth *dpth);
extern char *dpth_mk(struct dpth *dpth);
extern char *dpth_get_save_path(struct dpth *dpth);

extern int dpth_fwrite(struct dpth *dpth,
	struct iobuf *iobuf, struct blk *blk);

extern int dpth_release_all(struct dpth *dpth);

#endif
