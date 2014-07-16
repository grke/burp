#include "include.h"

static int receive_file(struct asfd *asfd, const char *autoupgrade_dir,
	const char *file, struct conf *conf)
{
	int ret=0;
	char *incoming=NULL;
	if(!(incoming=prepend_s(autoupgrade_dir, file))) return -1;
	ret=receive_a_file(asfd, incoming, conf);
	if(incoming) free(incoming);
	return ret;
}

static enum asl_ret autoupgrade_func(struct asfd *asfd,
	struct conf *conf, void *param)
{
	if(!strcmp(asfd->rbuf->buf, "do not autoupgrade"))
		return ASL_END_OK;
	if(strcmp(asfd->rbuf->buf, "autoupgrade ok"))
	{
		iobuf_log_unexpected(asfd->rbuf, __func__);
		return ASL_END_ERROR;
	}
	return ASL_END_OK_RETURN_1;
}

int autoupgrade_client(struct async *as, struct conf *conf)
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
	struct asfd *asfd;
	asfd=as->asfd;

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
	if(!(copy=strdup_w(conf->autoupgrade_dir, __func__)))
		goto end;

	strip_trailing_slashes(&copy);
	if((cp=strchr(copy, '/'))) *cp='\0';
	if(mkpath(&(conf->autoupgrade_dir), copy))
		goto end;

	// Let the server know we are ready.
	snprintf(write_str, sizeof(write_str),
		"autoupgrade:%s", conf->autoupgrade_os);
	if(asfd->write_str(asfd, CMD_GEN, write_str))
		goto end;

	if(!(a=asfd->simple_loop(asfd,
		conf, NULL, __func__, autoupgrade_func)))
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

	if(receive_file(asfd, conf->autoupgrade_dir, script_name, conf))
	{
		logp("Problem receiving %s/%s\n",
			conf->autoupgrade_dir, script_name);
		goto end;
	}
	if(receive_file(asfd, conf->autoupgrade_dir, package_name, conf))
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
	ret=run_script(asfd, args, NULL, conf,
		0 /* do not wait */, 1 /* use logp */, 1 /* use logw */);
	/* To get round Windows problems to do with installing over files
	   that the current process is running from, I am forking the child,
	   then immediately exiting the parent process. */

	printf("\n");
	logp("The server tried to upgrade your client.\n");
	logp("You will need to try your command again.\n");
	asfd_free(&as->asfd);

	exit(0);
end:
	if(copy) free(copy);
	if(script_path) free(script_path);
	iobuf_free(&rbuf);
	return ret;
}
