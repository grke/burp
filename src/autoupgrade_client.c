#include "burp.h"
#include "prog.h"
#include "counter.h"
#include "msg.h"
#include "handy.h"
#include "cmd.h"
#include "asyncio.h"
#include "berrno.h"
#include "client_vss.h"
#include "autoupgrade_client.h"

static int receive_file(const char *autoupgrade_dir, const char *file, struct cntr *p1cntr)
{
	int ret=0;
	char *incoming=NULL;
	if(!(incoming=prepend_s(autoupgrade_dir, file, strlen(file))))
		return -1;
	ret=receive_a_file(incoming, p1cntr);
	if(incoming) free(incoming);
	return ret;
}

int autoupgrade_client(struct config *conf, struct cntr *p1cntr)
{
	int a=0;
	int ret=-1;
	char *cp=NULL;
	char *copy=NULL;
	char *buf=NULL;
	size_t len=0;
	char cmd='\0';
	char *script_path=NULL;
	char script_name[32]="";
	char package_name[32]="";
	char write_str[256]="";
	const char *args[2];

	if(!conf->autoupgrade_dir)
	{
		logp("autoupgrade_dir not set!\n");
		goto end;
	}
	if(!conf->autoupgrade_os)
	{
		logp("autoupgrade_os not set!\n");
		goto end;
	}
	if(!(copy=strdup(conf->autoupgrade_dir)))
	{
		log_out_of_memory(__FUNCTION__);
		goto end;
	}
	// strip trailing slash
	if(copy[strlen(copy)-1]=='/') copy[strlen(copy)-1]='\0';
	if((cp=strchr(copy, '/'))) *cp='\0';
	if(mkpath(&(conf->autoupgrade_dir), copy))
		goto end;

	// Let the server know we are ready.
	snprintf(write_str, sizeof(write_str),
		"autoupgrade:%s", conf->autoupgrade_os);
	if(async_write_str(CMD_GEN, write_str))
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

#ifdef HAVE_WIN32
	win32_enable_backup_privileges(1 /* ignore_errors */);
	snprintf(script_name, sizeof(script_name), "script.bat");
	snprintf(package_name, sizeof(package_name), "package.exe");
#else
	snprintf(script_name, sizeof(script_name), "script");
	snprintf(package_name, sizeof(package_name), "package");
#endif

	if(receive_file(conf->autoupgrade_dir, script_name, p1cntr))
	{
		logp("Problem receiving %s/%s\n",
			conf->autoupgrade_dir, script_name);
		goto end;
	}
	if(receive_file(conf->autoupgrade_dir, package_name, p1cntr))
	{
		logp("Problem receiving %s/%s\n",
			conf->autoupgrade_dir, package_name);
		goto end;
	}

	if(!(script_path=prepend_s(conf->autoupgrade_dir,
		script_name, strlen(script_name)))) goto end;

	chmod(script_path, 0755);

	/* Run the script here. */
	a=0;
	args[a++]=script_path;
	args[a++]=NULL;
	ret=run_script(args, NULL, 0,
		p1cntr, 0 /* do not wait */, 1 /* use logp */);
	/* To get round Windows problems to do with installing over files
	   that the current process is running from, I am forking the child,
	   then immediately exiting the parent process. */

	printf("\n");
	logp("The server tried to upgrade your client.\n");
	logp("You will need to try your command again.\n");
	async_free();

	exit(0);
end:
	if(copy) free(copy);
	if(buf) free(buf);
	if(script_path) free(script_path);
	return ret;
}
