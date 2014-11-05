#include "include.h"

// Return O for OK, -1 if the estimated size is greater than hard_quota 
int check_quota(struct async *as, struct conf *cconf)
{
	int ret=0;
	unsigned long long byte;

	byte=cconf->cntr->ent[(uint8_t)CMD_BYTES_ESTIMATED]->count;

	// Print error if the estimated size is greater than hard_quota
	if(cconf->hard_quota != 0 && byte > (unsigned long long)cconf->hard_quota)
	{
		logw(as->asfd, cconf, "Err: hard quota is reached");
		logp("bytes estimated: %Lu%s\n", byte, bytes_to_human(byte));
		logp("hard quota: %Lu%s\n", cconf->hard_quota, bytes_to_human(cconf->hard_quota));
		ret=-1;
	}
	else
	{
		// Print warning if the estimated size is greater than soft_quota
		if(cconf->soft_quota != 0 && byte > (unsigned long long)cconf->soft_quota)
		{
			logw(as->asfd, cconf, "soft quota is exceeded");
			logp("bytes estimated: %Lu%s\n", byte, bytes_to_human(byte));
			logp("soft quota: %Lu%s\n", cconf->soft_quota, bytes_to_human(cconf->soft_quota));
		}  
	}
	
	return ret;
}
