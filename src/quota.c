#include "burp.h"
#include "prog.h"
#include "counter.h"
#include "asyncio.h"
#include "log.h"
#include "quota.h"

static void quota_log_bytes(const char *msg,
	struct cntr *p1cntr, unsigned long quota)
{
	async_write_str(CMD_WARNING, msg);
	logp("bytes estimated: %llu%s\n",
		p1cntr->byte, bytes_to_human(p1cntr->byte));
	logp("%s: %lu%s\n", msg, quota, bytes_to_human(quota));
}

// Return O for OK, -1 if the estimated size is greater than hard_quota.
int check_quota(struct config *conf, struct cntr *p1cntr)
{
	if(conf->hard_quota && p1cntr->byte > conf->hard_quota)
	{
		quota_log_bytes("hard quota exceeded",
			p1cntr, conf->hard_quota);
		return -1;
	}

	if(conf->soft_quota && p1cntr->byte > conf->soft_quota)
		quota_log_bytes("soft quota exceeded",
			p1cntr, conf->soft_quota);
	
	return 0;
}
