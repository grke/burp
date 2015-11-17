#include "../../burp.h"
#include "../../alloc.h"
#include "sel.h"
#include "status_client_ncurses.h"

struct sel *sel_alloc(void)
{
	return (struct sel *)calloc_w(1, sizeof(struct sel), __func__);
}

void sel_free(struct sel **sel)
{
	free_v((void **)sel);
}
