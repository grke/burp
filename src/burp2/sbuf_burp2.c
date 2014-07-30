#include "include.h"

struct burp2 *sbuf_burp2_alloc(void)
{
	struct burp2 *burp2;
	if(!(burp2=(struct burp2 *)
		calloc_w(1, sizeof(struct burp2), __func__)))
			return NULL;
	bfile_setup_funcs(&burp2->bfd);
	return burp2;
}

void sbuf_burp2_free_content(struct burp2 *burp2)
{
	return; // Nothing to do.
}
