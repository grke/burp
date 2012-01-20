#include "burp.h"
#include "prog.h"
#include "counter.h"
#include "msg.h"
#include "handy.h"
#include "cmd.h"
#include "asyncio.h"
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
	int ret=-1;
	char *cp=NULL;
	char *copy=NULL;
	char *buf=NULL;
	size_t len=0;
	char cmd='\0';
	char *script_path=NULL;

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

	// Let the server know we are ready.
	if(async_write_str(CMD_GEN, "autoupgrade"))
		goto end;

	if(async_read(&cmd, &buf, &len))
		goto end;

	if(cmd==CMD_GEN)
	{
		if(!strcmp(buf, "do not autoupgrade"))
		{
			ret=0;
			goto end;
		}
		else if(strcmp(buf, "autoupgrade ok"))
		{
			logp("unexpected response to autoupgrade from server: %s\n", buf);
			goto end;
		}
	}
	else
	{
		logp("unexpected response to autoupgrade from server: %c:%s\n", cmd, buf);
		goto end;
	}

	if(receive_file(conf->autoupgrade_dir, "script", p1cntr))
	{
		logp("Problem receiving %s/%s\n",
			conf->autoupgrade_dir, "script");
		goto end;
	}
	if(receive_file(conf->autoupgrade_dir, "package", p1cntr))
	{
		logp("Problem receiving %s/%s\n",
			conf->autoupgrade_dir, "package");
		goto end;
	}

	if(!(script_path=prepend_s(conf->autoupgrade_dir,
		"script", strlen("script")))) goto end;

	chmod(script_path, 0755);

	/* Run the script here */
	ret=run_script(script_path,
		NULL, 0, NULL, NULL, NULL, NULL, NULL, p1cntr);

end:
	if(copy) free(copy);
	if(buf) free(buf);
	if(script_path) free(script_path);
	return ret;
}
