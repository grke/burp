#include "include.h"

int do_delete_client(struct async *as, struct conf *conf)
{
	char msg[128]="";
	snprintf(msg, sizeof(msg), "delete %s", conf->backup?conf->backup:"");
	if(async_write_str(as, CMD_GEN, msg)
	  || async_read_expect(as, CMD_GEN, "ok"))
		return -1;
	logp("Deletion in progress\n");
	return 0;
}
