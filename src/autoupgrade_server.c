#include "burp.h"
#include "prog.h"
#include "counter.h"
#include "handy.h"
#include "autoupgrade_server.h"

int autoupgrade_server(struct config *conf, struct cntr *p1cntr)
{
	int ret=0;
	FILE *fp=NULL;
	unsigned long long bytes=0;
	if(open_file_for_send(NULL, &fp, "filetosend", p1cntr)
	  || send_whole_file_gz("filetosend", "datapth", 0, &bytes, NULL,
		p1cntr, 9, /* compression */
		NULL, fp, NULL, 0))
	{
		ret=-1;
		goto end;
	}
end:
	close_file_for_send(NULL, &fp);
	return ret;
}
