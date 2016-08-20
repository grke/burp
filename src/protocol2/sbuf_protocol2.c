#include "protocol2/sbuf_protocol2.h"
#include "burp.h"
#include "alloc.h"

struct protocol2 *sbuf_protocol2_alloc(void)
{
	struct protocol2 *protocol2;
	if(!(protocol2=(struct protocol2 *)
		calloc_w(1, sizeof(struct protocol2), __func__)))
			return NULL;
	bfile_setup_funcs(&protocol2->bfd);
	return protocol2;
}

void sbuf_protocol2_free_content(struct protocol2 *protocol2)
{
	return; // Nothing to do.
}
