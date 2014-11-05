#include "burp.h"
#include "prog.h"
#include "counter.h"
#include "asyncio.h"
#include "log.h"
#include "quota.h"

// Return O for OK, -1 if the estimated size is greater than hard_quota 
int check_quota(struct config *conf, struct cntr *p1cntr)
{
	int ret=0;
	// Print error if the estimated size is greater than hard_quota
	if(conf->hard_quota != 0 && p1cntr->byte > conf->hard_quota)
	{
		logw(p1cntr, "Err: hard quota is reached");
		logp("bytes estimated: %Lu%s\n", p1cntr->byte, bytes_to_human(p1cntr->byte));
		logp("hard quota: %Lu%s\n", conf->hard_quota, bytes_to_human(conf->hard_quota));
		ret=-1;
	}
	else
	{
		// Print warning if the estimated size is greater than soft_quota
		if(conf->soft_quota != 0 && p1cntr->byte > conf->soft_quota)
		{
			logw(p1cntr, "soft quota is exceeded");
			logp("bytes estimated: %Lu%s\n", p1cntr->byte, bytes_to_human(p1cntr->byte));
			logp("soft quota: %Lu%s\n", conf->soft_quota, bytes_to_human(conf->soft_quota));
		}  
	}
	
	
	return ret;
}
