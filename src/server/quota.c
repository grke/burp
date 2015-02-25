#include "include.h"
#include "../cmd.h"

static void quota_log_bytes(struct async *as,
	const char *msg, unsigned long long byte, unsigned long quota)
{
	as->asfd->write_str(as->asfd, CMD_WARNING, msg);
	logp("Bytes estimated: %Lu%s\n", byte, bytes_to_human(byte));
	logp("%s: %Lu%s\n", msg, quota, bytes_to_human(quota));
}

// Return O for OK, -1 if the estimated size is greater than hard_quota 
int check_quota(struct async *as, struct conf **cconfs)
{
	unsigned long long byte;

	byte=cget_cntr(cconfs[OPT_CNTR])->ent[(uint8_t)CMD_BYTES_ESTIMATED]->count;

	if(cconf->hard_quota && byte > (unsigned long long)cconf->hard_quota)
	{
		quota_log_bytes(as,
			"Hard quota exceeded", byte, cconf->soft_quota);
		return -1;
	}

	if(cconf->soft_quota && byte > (unsigned long long)cconf->soft_quota)
		quota_log_bytes(as,
			"Soft quota exceeded", byte, cconf->soft_quota);
	
	return 0;
}
