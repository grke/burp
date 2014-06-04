#include "include.h"

struct burp2 *sbuf_burp2_alloc(void)
{
	return (struct burp2 *)calloc_w(1, sizeof(struct burp2), __func__);
}

void sbuf_burp2_free_content(struct burp2 *burp2)
{
	return; // Nothing to do.
}
