#include "include.h"

int check_for_rubble_protocol2(struct async *as, struct sdirs *sdirs,
	const char *incexc, int *resume, struct conf **cconfs)
{
	// FIX THIS - currently just deletes the interrupted backup.
	ssize_t len=0;
	char *real=NULL;
	char lnk[32]="";
	if((len=readlink(sdirs->working, lnk, sizeof(lnk)-1))<0)
		return 0;
	else if(!len)
	{
		unlink(sdirs->working);
		return 0;
	}
	lnk[len]='\0';
	if(!(real=prepend_s(sdirs->client, lnk)))
	{
		log_and_send_oom(as->asfd, __func__);
		return -1;
	}
	if(recursive_delete(real, "", 1))
	{
		char msg[256]="";
		snprintf(msg, sizeof(msg),
			"Could not remove interrupted directory: %s", real);
		log_and_send(as->asfd, msg);
		return -1;
	}
	unlink(sdirs->working);
	return 0;
}
