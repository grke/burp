#include "burp.h"
#include "prog.h"
#include "conf.h"
#include "ca_server.h"
#include "log.h"
#include "msg.h"
#include "handy.h"
#include "cmd.h"
#include "asyncio.h"
#include "current_backups_server.h"

static int setup_stuff_done=0;

/* Remember the directory so that it can be used later for client certificate
   signing requests. */
static char *gca_dir=NULL;

static char *get_ca_dir(struct config *conf)
{
	FILE *fp=NULL;
	char buf[4096]="";
	if(!(fp=open_file(conf->ca_conf, "r"))) return NULL;
	while(fgets(buf, sizeof(buf), fp))
	{
		char *field=NULL;
		char *value=NULL;
		if(config_get_pair(buf, &field, &value)
		  || !field || !value) continue;

		if(!strcasecmp(field, "CA_DIR"))
		{
			if(!(gca_dir=strdup(value)))
			{
				log_out_of_memory(__FUNCTION__);
				fclose(fp);
				return NULL;
			}
			break;
		}
	}
	fclose(fp);
	return gca_dir;
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
	int a=0;
	const char *args[15];
	char linktarget[1024]="";

	if(is_dir_lstat(ca_dir)) return 0;

	setup_stuff_done++;

	logp("Initialising %s\n", ca_dir);
	logp("Running '%s --init --ca %s --dir %s --config %s'\n",
		conf->ca_burp_ca, conf->ca_name, ca_dir, conf->ca_conf);
	args[a++]=conf->ca_burp_ca;
	args[a++]="--init";
	args[a++]="--ca";
	args[a++]=conf->ca_name;
	args[a++]="--dir";
	args[a++]=ca_dir;
	args[a++]="--config";
	args[a++]=conf->ca_conf;
	args[a++]=NULL;
	if(run_script(args, NULL, 0, NULL /* cntr */, 1 /* wait */,
		0 /* do not use logp - stupid openssl prints lots of dots
		     one at a time with no way to turn it off */))
	{
		logp("Error running %s\n", conf->ca_burp_ca);
		return -1;
	}

	logp("Generating server key and cert signing request\n");
	logp("Running '%s --key --request --name %s --dir %s --config %s'\n",
		conf->ca_burp_ca, conf->ca_server_name, ca_dir, conf->ca_conf);
	a=0;
	args[a++]=conf->ca_burp_ca;
	args[a++]="--key";
	args[a++]="--request";
	args[a++]="--name";
	args[a++]=conf->ca_server_name;
	args[a++]="--dir";
	args[a++]=ca_dir;
	args[a++]="--config";
	args[a++]=conf->ca_conf;
	args[a++]=NULL;
	if(run_script(args, NULL, 0, NULL /* cntr */, 1 /* wait */,
		0 /* do not use logp - stupid openssl prints lots of dots
		     one at a time with no way to turn it off */))
	{
		logp("Error running %s\n", conf->ca_burp_ca);
		return -1;
	}

	logp("Signing request\n");
	logp("Running '%s --sign --ca %s --name %s --batch --dir %s --config %s'\n",
		conf->ca_burp_ca, conf->ca_name, conf->ca_server_name, ca_dir, conf->ca_conf);
	a=0;
	args[a++]=conf->ca_burp_ca;
	args[a++]="--sign";
	args[a++]="--ca";
	args[a++]=conf->ca_name;
	args[a++]="--name";
	args[a++]=conf->ca_server_name;
	args[a++]="--batch";
	args[a++]="--dir";
	args[a++]=ca_dir;
	args[a++]="--config";
	args[a++]=conf->ca_conf;
	args[a++]=NULL;
	if(run_script(args, NULL, 0, NULL /* cntr */, 1 /* wait */,
		0 /* do not use logp - stupid openssl prints lots of dots
		     one at a time with no way to turn it off */))
	{
		logp("Error running %s\n", conf->ca_burp_ca);
		return -1;
	}

	snprintf(linktarget, sizeof(linktarget), "%s/CA_%s.crt",
		ca_dir, conf->ca_name);
	if(strcmp(linktarget, conf->ssl_cert_ca))
	{
		remove_file(conf->ssl_cert_ca);
		if(symlink_file(linktarget, conf->ssl_cert_ca)) return -1;
	}

	snprintf(linktarget, sizeof(linktarget), "%s/%s.crt",
		ca_dir, conf->ca_server_name);
	if(strcmp(linktarget, conf->ssl_cert))
	{
		remove_file(conf->ssl_cert);
		if(symlink_file(linktarget, conf->ssl_cert)) return -1;
	}

	snprintf(linktarget, sizeof(linktarget), "%s/%s.key",
		ca_dir, conf->ca_server_name);
	if(strcmp(linktarget, conf->ssl_key))
	{
		remove_file(conf->ssl_key);
		if(symlink_file(linktarget, conf->ssl_key)) return -1;
	}

	return 0;
}

static int maybe_make_dhfile(struct config *conf, const char *ca_dir)
{
	int a=0;
	const char *args[12];
	char *path=NULL;
	struct stat statp;
	if(!lstat(conf->ssl_dhfile, &statp))
	{
		free(path);
		return 0;
	}

	setup_stuff_done++;

	logp("Creating %s\n", conf->ssl_dhfile);
	logp("Running '%s --dhfile %s --dir %s'\n",
		conf->ca_burp_ca, conf->ssl_dhfile, ca_dir);
	a=0;
	args[a++]=conf->ca_burp_ca;
	args[a++]="--dhfile";
	args[a++]=conf->ssl_dhfile;
	args[a++]="--dir";
	args[a++]=ca_dir;
	args[a++]=NULL;
	if(run_script(args, NULL, 0, NULL /* cntr */, 1 /* wait */,
		0 /* do not use logp - stupid openssl prints lots of dots
		     one at a time with no way to turn it off */))
	{
		logp("Error running %s\n", conf->ca_burp_ca);
		free(path);
		return -1;
	}

	free(path);
	return 0;
}

int ca_server_setup(struct config *conf)
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
		recursive_delete(ca_dir, "", TRUE);
		ret=-1;
		goto end;
	}

end:
	// Keeping it in gca_dir for later.
	//if(ca_dir) free(ca_dir);
	if(setup_stuff_done)
	{
		if(ret) logp("CA setup failed\n");
		else logp("CA setup succeeded\n");
	}
	return ret;
}

/* Return 1 for everything OK, signed and returned, -1 for error */
static int sign_client_cert(const char *client, struct config *conf)
{
	int a=0;
	int ret=-1;
	char msg[256]="";
	char csrpath[512]="";
	char crtpath[512]="";
	struct stat statp;
	const char *args[15];
	snprintf(csrpath, sizeof(csrpath), "%s/%s.csr", gca_dir, client);
	snprintf(crtpath, sizeof(crtpath), "%s/%s.crt", gca_dir, client);

	if(!strcmp(client, conf->ca_name))
	{
		char msg[512]="";
		snprintf(msg, sizeof(msg), "Will not accept a client certificate request with the same name as the CA (%s)!", conf->ca_name);
		log_and_send(msg);
		// Do not goto end, as it will delete things;
		return -1;
	}

	if(!lstat(crtpath, &statp))
	{
		char msg[512]="";
		snprintf(msg, sizeof(msg), "Will not accept a client certificate request for '%s' - %s already exists!", client, crtpath);
		log_and_send(msg);
		// Do not goto end, as it will delete things;
		return -1;
	}

	if(!lstat(csrpath, &statp))
	{
		char msg[512]="";
		snprintf(msg, sizeof(msg), "Will not accept a client certificate request for '%s' - %s already exists!", client, csrpath);
		log_and_send(msg);
		// Do not goto end, as it will delete things;
		return -1;
	}

	// Tell the client that we will do it, and send the server name at the
	// same time.
	snprintf(msg, sizeof(msg), "csr ok:%s", conf->ca_server_name);
	if(async_write_str(CMD_GEN, msg))
	{
		// Do not goto end, as it will delete things;
		return -1;
	}

	/* After this point, we might have uploaded files, so on error, go
	   to end and delete any new files. */

	// Get the CSR from the client.
	if(receive_a_file(csrpath, conf->p1cntr)) goto end;

	// Now, sign it.
	logp("Signing certificate signing request from %s\n", client);
	logp("Running '%s --name %s --ca %s --sign --batch --dir %s --config %s'\n", conf->ca_burp_ca, client, conf->ca_name, gca_dir, conf->ca_conf);
	a=0;
	args[a++]=conf->ca_burp_ca;
	args[a++]="--name";
	args[a++]=client;
	args[a++]="--ca";
	args[a++]=conf->ca_name;
	args[a++]="--sign";
	args[a++]="--batch";
	args[a++]="--dir";
	args[a++]=gca_dir;
	args[a++]="--config";
	args[a++]=conf->ca_conf;
	args[a++]=NULL;
	if(run_script(args, NULL, 0, NULL /* cntr */, 1 /* wait */,
		0 /* do not use logp - stupid openssl prints lots of dots
		     one at a time with no way to turn it off */))
	{
		logp("Error running %s\n", conf->ca_burp_ca);
		goto end;
	}

	// Now, we should have a signed certificate.
	// Need to send it back to the client.
	if(send_a_file(crtpath, conf->p1cntr))
		goto end;

	// Also need to send the CA public certificate back to the client.
	if(send_a_file(conf->ssl_cert_ca, conf->p1cntr))
		goto end;

	ret=1;
end:
	if(ret<0)
	{
		unlink(crtpath);
		unlink(csrpath);
	}
	return ret;
}

/* Return 1 for everything OK, signed and returned, -1 for error, 0 for
   nothing done. */
int ca_server_maybe_sign_client_cert(const char *client, const char *cversion, struct config *conf)
{
	int ret=0;
	char *buf=NULL;
	long min_ver=0;
	long cli_ver=0;

	if((min_ver=version_to_long("1.3.2"))<0
	 || (cli_ver=version_to_long(cversion))<0)
		return -1;
	// Clients before 1.3.2 did not know how to send cert signing requests.
	if(cli_ver<min_ver) return 0;

	while(1)
	{
		char cmd;
		size_t len=0;
		if(async_read(&cmd, &buf, &len))
		{
			ret=-1;
			break;
		}
		if(cmd==CMD_GEN)
		{
			if(!strcmp(buf, "csr"))
			{
				// Client wants to sign a certificate.
				logp("Client %s wants a certificate signed\n",
					client);
				if(!conf->ca_conf || !gca_dir)
				{
					logp("But server is not configured to sign client certificate requests.\n");
					logp("See option 'ca_conf'.\n");
					async_write_str(CMD_ERROR, "server not configured to sign client certificates");
					ret=-1;
					break;
				}
				// sign_client_cert() will return 1 for
				// everything signed and returned, or -1
				// for error
				ret=sign_client_cert(client, conf);
				break;

			}
			else if(!strcmp(buf, "nocsr"))
			{
				// Client does not want to sign a certificate.
				// No problem, just carry on.
				logp("Client %s does not want a certificate signed\n", client);
				ret=async_write_str(CMD_GEN, "nocsr ok");
				break;
			}
			else
			{
				logp("unexpected command from client when expecting csr: %c:%s\n", cmd, buf);
				ret=-1;
				break;
			}
		}
		else
		{
			logp("unexpected command from client when expecting csr: %c:%s\n", cmd, buf);
			ret=-1;
			break;
		}

		if(buf) free(buf); buf=NULL;
	}

	if(buf) free(buf);
	return ret;
}
