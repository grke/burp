#include "burp.h"
#include "prog.h"
#include "msg.h"
#include "handy.h"
#include "asyncio.h"
#include "delete_client.h"

int do_delete_client(struct config *conf)
{
	char msg[128]="";
	snprintf(msg, sizeof(msg), "delete %s", conf->backup?conf->backup:"");
	if(async_write_str(CMD_GEN, msg)
	  || async_read_expect(CMD_GEN, "ok"))
		return -1;
	logp("Deletion in progress\n");
	return 0;
}
