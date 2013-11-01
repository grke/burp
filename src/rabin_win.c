#include <stdio.h>

#include "rconf.h"
#include "rabin_win.h"
#include "log.h"

struct win *win_alloc(struct rconf *rconf)
{
	struct win *win=NULL;
	if((win=(struct win *)calloc(1, sizeof(struct win)))
	  && (win->data=(char *)calloc(1, sizeof(char)*rconf->win)))
		return win;
	log_out_of_memory(__FUNCTION__);
	win_free(win);
	return NULL;
}

void win_free(struct win *win)
{
	if(!win) return;
	if(win->data) free(win->data);
	free(win);
}
