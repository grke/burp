#include "../burp.h"
#include "../asfd.h"
#include "../async.h"
#include "../cmd.h"
#include "../cntr.h"
#include "../log.h"
#include "quota.h"

static void quota_log_bytes(struct async *as,
	const char *msg, uint64_t byte, uint64_t quota)
{
	as->asfd->write_str(as->asfd, CMD_WARNING, msg);
	logp("Bytes estimated: %" PRIu64 "%s\n", byte, bytes_to_human(byte));
	logp("%s: %" PRIu64 "%s\n", msg, quota, bytes_to_human(quota));
}

// Return O for OK, -1 if the estimated size is greater than hard_quota 
int check_quota(struct async *as, struct cntr *cntr,
	uint64_t hard_quota, uint64_t soft_quota)
{
	uint64_t byte;

	byte=cntr->ent[(uint8_t)CMD_BYTES_ESTIMATED]->count;

	if(hard_quota && byte>hard_quota)
	{
		quota_log_bytes(as, "Hard quota exceeded", byte, soft_quota);
		return -1;
	}

	if(soft_quota && byte>soft_quota)
		quota_log_bytes(as, "Soft quota exceeded", byte, soft_quota);
	
	return 0;
}
