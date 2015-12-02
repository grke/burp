#include "../../burp.h"
#include "../../alloc.h"
#include "../../bu.h"
#include "../../cstat.h"
#include "lline.h"
#include "sel.h"
#include "status_client_ncurses.h"

struct sel *sel_alloc(void)
{
	return (struct sel *)calloc_w(1, sizeof(struct sel), __func__);
}

static void sel_free_content(struct sel *sel)
{
	if(!sel) return;
	cstat_list_free(&sel->clist);
	llines_free(&sel->llines);
	// Will be freed elsewhere.
	//bu_list_free(&sel->backup);
}

void sel_free(struct sel **sel)
{
	if(!sel || !*sel) return;
	sel_free_content(*sel);
	free_v((void **)sel);
}
