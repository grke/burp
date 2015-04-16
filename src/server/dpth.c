#include "../burp.h"
#include "../alloc.h"
#include "../fsops.h"
#include "../lock.h"
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
