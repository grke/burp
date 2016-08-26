#include "../burp.h"
#include "../asfd.h"
#include "../cmd.h"
#include "../log.h"
#include "delete.h"

int do_delete_client(struct asfd *asfd, struct conf **confs)
{
	char msg[128]="";
	const char *backup=get_string(confs[OPT_BACKUP]);
	snprintf(msg, sizeof(msg), "Delete %s", backup?backup:"");
	if(asfd->write_str(asfd, CMD_GEN, msg)
	  || asfd_read_expect(asfd, CMD_GEN, "ok"))
		return -1;
	logp("Deletion in progress\n");
	return 0;
}
