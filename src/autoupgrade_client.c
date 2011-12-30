#include "burp.h"
#include "prog.h"
#include "counter.h"
#include "msg.h"
#include "handy.h"
#include "autoupgrade_client.h"

static int receive_file(const char *autoupgrade_dir, const char *file, struct cntr *p1cntr)
{
	int ret=0;
	FILE *fp=NULL;
	char *incoming=NULL;
	unsigned long long rcvdbytes=0;
	unsigned long long sentbytes=0;

	if(!(incoming=prepend_s(autoupgrade_dir, file, strlen(file))))
	{
		ret=-1;
		goto end;
	}
	if(!(fp=open_file(incoming, "wb")))
	{
		ret=-1;
		goto end;
	}
	if(transfer_gzfile_in(incoming, NULL, fp, &rcvdbytes, &sentbytes,
		NULL, 0, p1cntr, NULL))
	{
		ret=-1;
		goto end;
	}
end:
	close_fp(&fp);
	if(!ret) logp("received: %s\n", incoming);
	if(incoming) free(incoming);
	return ret;
}

int autoupgrade_client(struct config *conf, struct cntr *p1cntr)
{
	int ret=-1; // always return failure, so as to exit
	char *cp=NULL;
	char *copy=NULL;
	logp("server wants to autoupgrade us\n");

	if(!conf->autoupgrade_dir)
	{
		logp("autoupgrade_dir not set!\n");
		goto end;
	}
	if(!(copy=strdup(conf->autoupgrade_dir)))
	{
		logp("out of memory\n");
		goto end;
	}
	// strip trailing slash
	if(copy[strlen(copy)-1]=='/') copy[strlen(copy)-1]='\0';
	if((cp=strchr(copy, '/'))) *cp='\0';
	if(mkpath(&(conf->autoupgrade_dir), copy))
		goto end;

	if(receive_file(conf->autoupgrade_dir, "script", p1cntr)
	  || receive_file(conf->autoupgrade_dir, "package", p1cntr))
		goto end;
end:
	if(copy) free(copy);
	return ret;
}
