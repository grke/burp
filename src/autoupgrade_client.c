#include "burp.h"
#include "prog.h"
#include "counter.h"
#include "msg.h"
#include "handy.h"
#include "autoupgrade_client.h"

int autoupgrade_client(struct config *conf, struct cntr *p1cntr)
{
	int ret=0;
	FILE *fp=NULL;
	unsigned long long rcvdbytes=0;
	unsigned long long sentbytes=0;
	logp("server wants to autoupgrade us\n");
	if(!(fp=open_file("/tmp/receive", "wb")))
	{
		ret=-1;
		goto end;
	}
	if(transfer_gzfile_in("/tmp/receive", NULL, fp,
		&rcvdbytes, &sentbytes,
		NULL, 0, p1cntr, NULL))
	{
		ret=-1;
		goto end;
	}
end:
	close_fp(&fp);
	return ret;
}
