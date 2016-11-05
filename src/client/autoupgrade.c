#include "../burp.h"
#include "../asfd.h"
#include "../async.h"
#include "../cmd.h"
#include "../fsops.h"
#include "../iobuf.h"
#include "../handy.h"
#include "../log.h"
#include "../prepend.h"
#include "../run_script.h"
#include "cvss.h"
#include "autoupgrade.h"

static int receive_file(struct asfd *asfd, const char *autoupgrade_dir,
	const char *file, struct cntr *cntr)
{
	int ret=0;
	char *incoming=NULL;
	if(!(incoming=prepend_s(autoupgrade_dir, file))) return -1;
	ret=receive_a_file(asfd, incoming, cntr);
	free_w(&incoming);
	return ret;
}

static enum asl_ret autoupgrade_func(struct asfd *asfd,
	__attribute__ ((unused)) struct conf **confs,
	__attribute__ ((unused)) void *param)
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

int autoupgrade_client(struct async *as, struct conf **confs)
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
	char *autoupgrade_dir=get_string(confs[OPT_AUTOUPGRADE_DIR]);
	const char *autoupgrade_os=get_string(confs[OPT_AUTOUPGRADE_OS]);
	struct cntr *cntr=get_cntr(confs);
	asfd=as->asfd;

	if(!autoupgrade_dir)
	{
		logp("autoupgrade_dir not set!\n");
		goto end;
	}
	if(!autoupgrade_os)
	{
		logp("autoupgrade_os not set!\n");
		goto end;
	}
	if(!(copy=strdup_w(autoupgrade_dir, __func__)))
		goto end;

	strip_trailing_slashes(&copy);
	if((cp=strchr(copy, '/'))) *cp='\0';
	if(mkpath(&autoupgrade_dir, copy))
		goto end;

	// Let the server know we are ready.
	snprintf(write_str, sizeof(write_str),
		"autoupgrade:%s", autoupgrade_os);
	if(asfd->write_str(asfd, CMD_GEN, write_str))
		goto end;

	if(!(a=asfd->simple_loop(asfd,
		confs, NULL, __func__, autoupgrade_func)))
	{
		ret=0; // No autoupgrade.
		goto end;
	}
	else if(a<0) // Error.
		goto end;

#ifdef HAVE_WIN32
	win32_enable_backup_privileges();
	snprintf(script_name, sizeof(script_name), "script.bat");
	snprintf(package_name, sizeof(package_name), "package.exe");
#else
	snprintf(script_name, sizeof(script_name), "script");
	snprintf(package_name, sizeof(package_name), "package");
#endif

	if(receive_file(asfd, autoupgrade_dir, script_name, cntr))
	{
		logp("Problem receiving %s/%s\n",
			autoupgrade_dir, script_name);
		goto end;
	}
	if(receive_file(asfd, autoupgrade_dir, package_name, cntr))
	{
		logp("Problem receiving %s/%s\n",
			autoupgrade_dir, package_name);
		goto end;
	}

	if(!(script_path=prepend_s(autoupgrade_dir, script_name)))
		goto end;

	chmod(script_path, 0755);

	/* Run the script here. */
	a=0;
	args[a++]=script_path;
	args[a++]=NULL;
	run_script(asfd, args, NULL, confs,
		0 /* do not wait */, 1 /* use logp */, 1 /* log_remote */);
	/* To get round Windows problems to do with installing over files
	   that the current process is running from, I am forking the child,
	   then immediately exiting the parent process. */

	printf("\n");
	logp("The server tried to upgrade your client.\n");
	logp("You will need to try your command again.\n");
	asfd_flush_asio(asfd);
	asfd_free(&as->asfd);

	exit(0);
end:
	free_w(&copy);
	free_w(&script_path);
	iobuf_free(&rbuf);
	return ret;
}
