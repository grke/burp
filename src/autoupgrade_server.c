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
int autoupgrade_server(long ser_ver, long cli_ver, const char *os, struct config *conf, struct cntr *p1cntr)
{
	int ret=-1;
	char *path=NULL;
	char *base_path=NULL;
	char *script_path=NULL;
	char *package_path=NULL;
	char *script_path_top=NULL;
	char *script_path_specific=NULL;
	struct stat stats;
	struct stat statp;

	if(!conf->autoupgrade_dir)
	{
		// Autoupgrades not turned on on the server.
		ret=0;
		async_write_str(CMD_GEN, "do not autoupgrade");
		goto end;
	}

	if(cli_ver>=ser_ver)
	{
		// No need to upgrade - client is same version as server,
		// or newer.
		ret=0;
		async_write_str(CMD_GEN, "do not autoupgrade");
		goto end;
	}

	if(!(base_path=prepend_s(conf->autoupgrade_dir, os, strlen(os)))
	  || !(path=prepend_s(base_path, VERSION, strlen(VERSION)))
	  || !(script_path_top=prepend_s(base_path, "script", strlen("script")))
	  || !(script_path_specific=prepend_s(path, "script", strlen("script")))
	  || !(package_path=prepend_s(path, "package", strlen("package"))))
	{
		async_write_str(CMD_GEN, "do not autoupgrade");
		goto end;
	}

	if(!stat(script_path_specific, &stats))
		script_path=script_path_specific;
	else if(!stat(script_path_top, &stats))
		script_path=script_path_top;
	else
	{
		logp("Want to autoupgrade client, but no file at:\n");
		logp("%s\n", script_path_top);
		logp("or:\n");
		logp("%s\n", script_path_specific);
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
	/* Clients currently exit after forking, so exit ourselves. */
	logp("Expecting client to upgrade - now exiting\n");
	async_free();
	exit(0);
end:
	if(path) free(path);
	if(base_path) free(base_path);
	if(script_path_specific) free(script_path_specific);
	if(script_path_top) free(script_path_top);
	if(package_path) free(package_path);
	return ret;
}
