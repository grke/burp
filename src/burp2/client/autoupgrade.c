#include "include.h"

static int receive_file(struct async *as, const char *autoupgrade_dir,
	const char *file, struct conf *conf)
{
	int ret=0;
	char *incoming=NULL;
	if(!(incoming=prepend_s(autoupgrade_dir, file))) return -1;
	ret=receive_a_file(as, incoming, conf);
	if(incoming) free(incoming);
	return ret;
}

static enum asl_ret autoupgrade_func(struct async *as, struct iobuf *rbuf,
	struct conf *conf, void *param)
{
	if(!strcmp(rbuf->buf, "do not autoupgrade"))
		return ASL_END_OK;
	if(strcmp(rbuf->buf, "autoupgrade ok"))
	{
		iobuf_log_unexpected(rbuf, __FUNCTION__);
		return ASL_END_ERROR;
	}
	return ASL_END_OK_RETURN_1;
}

int autoupgrade_client(struct async **as, struct conf *conf)
{
	int a=0;
	int ret=-1;
	char *cp=NULL;
	char *copy=NULL;
	char *script_path=NULL;
	char script_name[32]="";
	char package_name[32]="";
	char write_str[256]="";
	const char *args[2];
	struct iobuf *rbuf=NULL;

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
	if(async_write_str(*as, CMD_GEN, write_str))
		goto end;

	if(!(a=async_simple_loop(*as,
		conf, NULL, __FUNCTION__, autoupgrade_func)))
	{
		ret=0; // No autoupgrade.
		goto end;
	}
	else if(a<0) // Error.

#ifdef HAVE_WIN32
	win32_enable_backup_privileges();
	snprintf(script_name, sizeof(script_name), "script.bat");
	snprintf(package_name, sizeof(package_name), "package.exe");
#else
	snprintf(script_name, sizeof(script_name), "script");
	snprintf(package_name, sizeof(package_name), "package");
#endif

	if(receive_file(*as, conf->autoupgrade_dir, script_name, conf))
	{
		logp("Problem receiving %s/%s\n",
			conf->autoupgrade_dir, script_name);
		goto end;
	}
	if(receive_file(*as, conf->autoupgrade_dir, package_name, conf))
	{
		logp("Problem receiving %s/%s\n",
			conf->autoupgrade_dir, package_name);
		goto end;
	}

	if(!(script_path=prepend_s(conf->autoupgrade_dir, script_name)))
		goto end;

	chmod(script_path, 0755);

	/* Run the script here. */
	a=0;
	args[a++]=script_path;
	args[a++]=NULL;
	ret=run_script(*as, args, NULL, conf,
		0 /* do not wait */, 1 /* use logp */, 1 /* use logw */);
	/* To get round Windows problems to do with installing over files
	   that the current process is running from, I am forking the child,
	   then immediately exiting the parent process. */

	printf("\n");
	logp("The server tried to upgrade your client.\n");
	logp("You will need to try your command again.\n");
	async_free(as);

	exit(0);
end:
	if(copy) free(copy);
	if(script_path) free(script_path);
	iobuf_free(rbuf);
	return ret;
}
