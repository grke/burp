#include "include.h"
#include "../cmd.h"

int do_delete_client(struct asfd *asfd, struct conf *conf)
{
	char msg[128]="";
	snprintf(msg, sizeof(msg), "Delete %s", conf->backup?conf->backup:"");
	if(asfd->write_str(asfd, CMD_GEN, msg)
	  || asfd->read_expect(asfd, CMD_GEN, "ok"))
		return -1;
	logp("Deletion in progress\n");
	return 0;
}
