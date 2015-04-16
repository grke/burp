#include "../burp.h"
#include "../alloc.h"
#include "../fsops.h"
#include "../lock.h"
#include "../log.h"
#include "dpth.h"

struct dpth *dpth_alloc(void)
{
        return (struct dpth *)calloc_w(1, sizeof(struct dpth), __func__);
}

void dpth_free(struct dpth **dpth)
{
	if(!dpth || !*dpth) return;
	dpth_release_all(*dpth);
	free_w(&((*dpth)->base_path));
	free_v((void **)dpth);
}

int dpth_release_and_move_to_next_in_list(struct dpth *dpth)
{
	int ret=0;
	struct dpth_lock *next=NULL;

	// Try to release (and unlink) the lock even if close_fp failed, just
	// to be tidy.
	if(close_fp(&dpth->fp)) ret=-1;
	if(lock_release(dpth->head->lock)) ret=-1;
	lock_free(&dpth->head->lock);

	next=dpth->head->next;
	if(dpth->head==dpth->tail) dpth->tail=next;
	free_v((void **)&dpth->head);
	dpth->head=next;
	return ret;
}

int dpth_release_all(struct dpth *dpth)
{
	int ret=0;
	if(!dpth) return 0;
	if(dpth->fp && close_fp(&dpth->fp)) ret=-1;
	while(dpth->head)
		if(dpth_release_and_move_to_next_in_list(dpth)) ret=-1;
	return ret;
}

#define MAX_FILES_PER_DIR       0xFFFF

static int incr(uint16_t *component, uint16_t max)
{
	if((*component)++<max) return 1;
	*component=0;
	return 0;
}

// Three levels with 65535 entries each gives
// 65535^3 = 281,462,092,005,375 data entries
// recommend a filesystem with lots of inodes?
// Hmm, but ext3 only allows 32000 subdirs, although that many files are OK.
int dpth_incr(struct dpth *dpth)
{
	if(incr(&dpth->tert, MAX_FILES_PER_DIR)
	  || incr(&dpth->seco, dpth->max_storage_subdirs)
	  || incr(&dpth->prim, dpth->max_storage_subdirs))
		return 0;
	logp("No free data file entries out of the %d*%d*%d available!\n",
		MAX_FILES_PER_DIR,
		dpth->max_storage_subdirs, dpth->max_storage_subdirs);
	logp("Maybe move the storage directory aside and start again.\n");
	return -1;
}
