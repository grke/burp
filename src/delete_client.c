#include "burp.h"
#include "prog.h"
#include "msg.h"
#include "handy.h"
#include "asyncio.h"
#include "delete_client.h"

int do_delete_client(struct config *conf)
{
	char msg[128]="";
	// Old clients will send 'delete'. Changed so that burp2 servers can
	// detect the difference and refuse to delete if they see 'delete'.
	// This is to avoid potential confusion with the future diff/long diff
	// options.
	snprintf(msg, sizeof(msg), "Delete %s", conf->backup?conf->backup:"");
	if(async_write_str(CMD_GEN, msg)
	  || async_read_expect(CMD_GEN, "ok"))
		return -1;
	logp("Deletion in progress\n");
	return 0;
}
