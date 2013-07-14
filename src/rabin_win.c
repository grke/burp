#include <stdio.h>

#include "rconf.h"
#include "rabin_win.h"

struct win *win_alloc(struct rconf *rconf)
{
	struct win *win=NULL;
	if((win=(struct win *)calloc(1, sizeof(struct win)))
	  && (win->data=(char *)calloc(1, sizeof(char)*rconf->win)))
		return win;
	fprintf(stderr, "Out of memory in %s\n", __FUNCTION__);
	if(win) free(win);
	return NULL;
}

void win_free(struct win *win)
{
	if(!win) return;
	free(win->data);
	free(win);
}
