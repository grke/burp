#include "burp.h"
#include "prog.h"
#include "counter.h"
#include "handy.h"
#include "cmd.h"
#include "asyncio.h"
#include "autoupgrade_server.h"

static int send_a_file(const char *path, struct cntr *p1cntr)
{
	int ret=0;
	FILE *fp=NULL;
	unsigned long long bytes=0;
	if(open_file_for_send(NULL, &fp, path, p1cntr)
	  || send_whole_file_gz(path, "datapth", 0, &bytes, NULL,
		p1cntr, 9, /* compression */
		NULL, fp, NULL, 0))
	{
		ret=-1;
		goto end;
	}
	logp("Sent %s\n", path);
end:
	close_file_for_send(NULL, &fp);
	return ret;
}

// Return -1 on error or success, 0 to continue normally.
int autoupgrade_server(long ser_ver, long cli_ver, struct config *cconf, struct cntr *p1cntr)
{
	int ret=-1;
	char *path=NULL;
	char *script_path=NULL;
	char *package_path=NULL;
	struct stat stats;
	struct stat statp;

	if(cli_ver>=ser_ver)
	{
		// No need to upgrade - client is same version as server,
		// or newer.
		ret=0;
		async_write_str(CMD_GEN, "do not autoupgrade");
		goto end;
	}

	if(!(path=prepend_s(cconf->autoupgrade_dir, VERSION, strlen(VERSION)))
	  || !(script_path=prepend_s(path, "script", strlen("script")))
	  || !(package_path=prepend_s(path, "package", strlen("package"))))
	{
		async_write_str(CMD_GEN, "do not autoupgrade");
		goto end;
	}

	if(stat(script_path, &stats))
	{
		logp("Want to autoupgrade client, but no file at:\n");
		logp("%s\n", script_path);
		ret=0; // this is probably OK
		async_write_str(CMD_GEN, "do not autoupgrade");
		goto end;
	}
	if(stat(package_path, &statp))
	{
		logp("Want to autoupgrade client, but no file available at:\n");
		logp("%s\n", package_path);
		ret=0; // this is probably OK
		async_write_str(CMD_GEN, "do not autoupgrade");
		goto end;
	}

	if(!S_ISREG(stats.st_mode))
	{
		logp("%s is not a regular file\n", script_path);
		async_write_str(CMD_GEN, "do not autoupgrade");
		goto end;
	}
	if(!S_ISREG(statp.st_mode))
	{
		logp("%s is not a regular file\n", package_path);
		async_write_str(CMD_GEN, "do not autoupgrade");
		goto end;
	}

	if(async_write_str(CMD_GEN, "autoupgrade ok"))
		goto end;

	if(send_a_file(script_path, p1cntr))
	{
		logp("Problem sending %s\n", script_path);
		goto end;
	}
	if(send_a_file(package_path, p1cntr))
	{
		logp("Problem sending %s\n", package_path);
		goto end;
	}
	ret=0;
end:
	if(path) free(path);
	if(script_path) free(script_path);
	if(package_path) free(package_path);
	return ret;
}
