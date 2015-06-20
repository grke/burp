#include "win.h"
#include "rconf.h"
#include "../../alloc.h"

struct win *win_alloc(struct rconf *rconf)
{
	struct win *win=NULL;
	if((win=(struct win *)calloc_w(1, sizeof(struct win), __func__))
	  && (win->data=(char *)calloc_w(
		1, sizeof(char)*rconf->win_size, __func__)))
			return win;
	win_free(win);
	return NULL;
}

void win_free(struct win *win)
{
	if(!win) return;
	if(win->data) free(win->data);
	free(win);
}
