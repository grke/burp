#include "burp.h"
#include "prog.h"
#include "conf.h"
#include "ca.h"
#include "log.h"
#include "msg.h"
#include "handy.h"

static int setup_stuff_done=0;

static char *get_ca_dir(struct config *conf)
{
	FILE *fp=NULL;
	char buf[4096]="";
	char *ret=NULL;
	if(!(fp=open_file(conf->ca_conf, "r"))) return NULL;
	while(fgets(buf, sizeof(buf), fp))
	{
		char *field=NULL;
		char *value=NULL;
		if(config_get_pair(buf, &field, &value)
		  || !field || !value) continue;

		if(!strcasecmp(field, "CA_DIR"))
		{
			if(!(ret=strdup(value)))
			{
				logp("out of memory");
				fclose(fp);
				return NULL;
			}
			break;
		}
	}
	fclose(fp);
	return ret;
}

static void remove_file(const char *path)
{
	logp("Removing %s\n", path);
	unlink(path);
}

static int symlink_file(const char *oldpath, const char *newpath)
{
	struct stat statp;
	logp("Symlinking %s to %s\n", newpath, oldpath);
	if(lstat(oldpath, &statp))
	{
		logp("Could not symlink: %s does not exist\n", oldpath);
		return -1;
	}
	if(symlink(oldpath, newpath))
	{
		logp("Could not symlink: %s does not exist\n", oldpath);
		return -1;
	}
	return 0;
}

static int burp_ca_init(struct config *conf, const char *ca_dir)
{
	char linktarget[1024]="";

	if(is_dir(ca_dir)) return 0;

	setup_stuff_done++;

	logp("Initialising %s\n", ca_dir);
	if(run_script(conf->ca_burp_ca, NULL, 0, "--init", "--ca",
		conf->ca_name, NULL, NULL, NULL, NULL /* cntr */, 1 /* wait */,
		0 /* do not use logp - stupid openssl prints lots of dots
		     one at a time with no way to turn it off */))
	{
		logp("error when running '%s --init --ca %s'\n",
			conf->ca_burp_ca, conf->ca_name);
		return -1;
	}

	logp("Generating server key and cert signing request\n");

	if(run_script(conf->ca_burp_ca, NULL, 0, "--key", "--request",
		"--name", conf->ca_server_name,
		NULL, NULL, NULL /* cntr */, 1 /* wait */,
		0 /* do not use logp - stupid openssl prints lots of dots
		     one at a time with no way to turn it off */))
	{
		logp("error when running '%s --key --request --name %s'\n",
			conf->ca_burp_ca, conf->ca_server_name);
		return -1;
	}

	logp("Signing request\n");

	if(run_script(conf->ca_burp_ca, NULL, 0, "--sign", "--ca",
		conf->ca_name, "--name", conf->ca_server_name, "--batch",
		NULL /* cntr */, 1 /* wait */,
		0 /* do not use logp - stupid openssl prints lots of dots
		     one at a time with no way to turn it off */))
	{
		logp("error when running '%s --key --request --name %s'\n",
			conf->ca_burp_ca, conf->ca_server_name);
		return -1;
	}

	remove_file(conf->ssl_cert_ca);
	remove_file(conf->ssl_cert);
	remove_file(conf->ssl_key);

	snprintf(linktarget, sizeof(linktarget), "%s/CA_%s.crt",
		ca_dir, conf->ca_name);
	if(symlink_file(linktarget, conf->ssl_cert_ca)) return -1;

	snprintf(linktarget, sizeof(linktarget), "%s/%s.crt",
		ca_dir, conf->ca_server_name);
	if(symlink_file(linktarget, conf->ssl_cert)) return -1;

	snprintf(linktarget, sizeof(linktarget), "%s/%s.key",
		ca_dir, conf->ca_server_name);
	if(symlink_file(linktarget, conf->ssl_key)) return -1;

	return 0;
}

static int maybe_make_dhfile(struct config *conf, const char *ca_dir)
{
	char *path=NULL;
	struct stat statp;
	if(!lstat(conf->ssl_dhfile, &statp))
	{
		free(path);
		return 0;
	}

	setup_stuff_done++;

	logp("Creating %s\n", conf->ssl_dhfile);

	if(run_script(conf->ca_burp_ca, NULL, 0, "--dhfile", conf->ssl_dhfile,
		NULL, NULL, NULL, NULL, NULL /* cntr */, 1 /* wait */,
		0 /* do not use logp - stupid openssl prints lots of dots
		     one at a time with no way to turn it off */))
	{
		logp("error when running '%s --dhfile %s'\n",
			conf->ca_burp_ca, path);
		free(path);
		return -1;
	}

	free(path);
	return 0;
}

int setup_ca(struct config *conf)
{
	int ret=0;
	char *ca_dir=NULL;

	if(!conf->ca_conf) return 0;

	/* Need to read CA_DIR from ca_conf. */
	if(!(ca_dir=get_ca_dir(conf)))
	{
		ret=-1;
		goto end;
	}

	if(maybe_make_dhfile(conf, ca_dir))
	{
		ret=-1;
		goto end;
	}

	if(burp_ca_init(conf, ca_dir))
	{
		ret=-1;
		goto end;
	}

end:
	if(ca_dir) free(ca_dir);
	if(setup_stuff_done)
	{
		if(ret) logp("CA setup failed\n");
		else logp("CA setup succeeded\n");
	}
	return ret;
}
