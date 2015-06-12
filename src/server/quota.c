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
	struct cntr *cntr=get_cntr(cconfs);
	ssize_t hard_quota=get_ssize_t(cconfs[OPT_HARD_QUOTA]);
	ssize_t soft_quota=get_ssize_t(cconfs[OPT_SOFT_QUOTA]);

	byte=cntr->ent[(uint8_t)CMD_BYTES_ESTIMATED]->count;

	if(hard_quota && byte > (unsigned long long)hard_quota)
	{
		quota_log_bytes(as, "Hard quota exceeded", byte, soft_quota);
		return -1;
	}

	if(soft_quota && byte > (unsigned long long)soft_quota)
		quota_log_bytes(as, "Soft quota exceeded", byte, soft_quota);
	
	return 0;
}
