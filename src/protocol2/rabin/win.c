#include "../../burp.h"
#include "win.h"
#include "rconf.h"
#include "../../alloc.h"

struct win *win_alloc(struct rconf *rconf)
{
	struct win *win=NULL;
	if(!(win=(struct win *)calloc_w(1, sizeof(struct win), __func__))
	  || !(win->data=(unsigned char *)calloc_w(
		1, sizeof(unsigned char)*rconf->win_size, __func__)))
			win_free(&win);
	return win;
}

static void win_free_content(struct win *win)
{
	if(!win) return;
	free_v((void **)&win->data);
}

void win_free(struct win **win)
{
	if(!win || !*win) return;
	win_free_content(*win);
	free_v((void **)win);
}
