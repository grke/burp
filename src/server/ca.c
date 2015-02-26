#include "include.h"
#include "../cmd.h"

static int setup_stuff_done=0;

/* Remember the directory so that it can be used later for client certificate
   signing requests. */
static char *gca_dir=NULL;

static char *get_ca_dir(struct conf **confs)
{
	FILE *fp=NULL;
	char buf[4096]="";
	const char *ca_conf=get_string(confs[OPT_CA_CONF]);
	if(!(fp=open_file(ca_conf, "r"))) goto end;
	while(fgets(buf, sizeof(buf), fp))
	{
		char *field=NULL;
		char *value=NULL;
		if(conf_get_pair(buf, &field, &value)
		  || !field || !value) continue;

		if(!strcasecmp(field, "CA_DIR"))
		{
			if(!(gca_dir=strdup_w(value, __func__)))
				goto end;
			break;
		}
	}
end:
	close_fp(&fp);
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

static int burp_ca_init(struct conf **confs, const char *ca_dir)
{
	int a=0;
	const char *args[15];
	char linktarget[1024]="";
	const char *ca_name=get_string(confs[OPT_CA_NAME]);
	const char *ca_conf=get_string(confs[OPT_CA_CONF]);
	const char *ca_burp_ca=get_string(confs[OPT_CA_BURP_CA]);
	const char *ca_server_name=get_string(confs[OPT_CA_SERVER_NAME]);
	const char *ssl_cert=get_string(confs[OPT_SSL_CERT]);
	const char *ssl_cert_ca=get_string(confs[OPT_SSL_CERT_CA]);
	const char *ssl_key=get_string(confs[OPT_SSL_KEY]);

	if(is_dir_lstat(ca_dir)) return 0;

	setup_stuff_done++;

	logp("Initialising %s\n", ca_dir);
	logp("Running '%s --init --ca %s --dir %s --config %s'\n",
		ca_burp_ca, ca_name, ca_dir, ca_conf);
	args[a++]=ca_burp_ca;
	args[a++]="--init";
	args[a++]="--ca";
	args[a++]=ca_name;
	args[a++]="--dir";
	args[a++]=ca_dir;
	args[a++]="--config";
	args[a++]=ca_conf;
	args[a++]=NULL;
	if(run_script(NULL /* no async yet */, args, NULL, confs, 1 /* wait */,
		0, 0 /* do not use logp - stupid openssl prints lots of dots
		        one at a time with no way to turn it off */))
	{
		logp("Error running %s\n", ca_burp_ca);
		return -1;
	}

	logp("Generating server key and cert signing request\n");
	logp("Running '%s --key --request --name %s --dir %s --config %s'\n",
		ca_burp_ca, ca_server_name, ca_dir, ca_conf);
	a=0;
	args[a++]=ca_burp_ca;
	args[a++]="--key";
	args[a++]="--request";
	args[a++]="--name";
	args[a++]=ca_server_name;
	args[a++]="--dir";
	args[a++]=ca_dir;
	args[a++]="--config";
	args[a++]=ca_conf;
	args[a++]=NULL;
	if(run_script(NULL /* no async yet */, args, NULL, confs, 1 /* wait */,
		0, 0 /* do not use logp - stupid openssl prints lots of dots
		        one at a time with no way to turn it off */))
	{
		logp("Error running %s\n", ca_burp_ca);
		return -1;
	}

	logp("Signing request\n");
	logp("Running '%s --sign --ca %s --name %s --batch --dir %s --config %s'\n",
		ca_burp_ca, ca_name, ca_server_name, ca_dir, ca_conf);
	a=0;
	args[a++]=ca_burp_ca;
	args[a++]="--sign";
	args[a++]="--ca";
	args[a++]=ca_name;
	args[a++]="--name";
	args[a++]=ca_server_name;
	args[a++]="--batch";
	args[a++]="--dir";
	args[a++]=ca_dir;
	args[a++]="--config";
	args[a++]=ca_conf;
	args[a++]=NULL;
	if(run_script(NULL /* no async yet */, args, NULL, confs, 1 /* wait */,
		0, 0 /* do not use logp - stupid openssl prints lots of dots
		        one at a time with no way to turn it off */))
	{
		logp("Error running %s\n", ca_burp_ca);
		return -1;
	}

	snprintf(linktarget, sizeof(linktarget), "%s/CA_%s.crt",
		ca_dir, ca_name);
	if(strcmp(linktarget, ssl_cert_ca))
	{
		remove_file(ssl_cert_ca);
		if(symlink_file(linktarget, ssl_cert_ca)) return -1;
	}

	snprintf(linktarget, sizeof(linktarget), "%s/%s.crt",
		ca_dir, ca_server_name);
	if(strcmp(linktarget, ssl_cert))
	{
		remove_file(ssl_cert);
		if(symlink_file(linktarget, ssl_cert)) return -1;
	}

	snprintf(linktarget, sizeof(linktarget), "%s/%s.key",
		ca_dir, ca_server_name);
	if(strcmp(linktarget, ssl_key))
	{
		remove_file(ssl_key);
		if(symlink_file(linktarget, ssl_key)) return -1;
	}

	return 0;
}

static int maybe_make_dhfile(struct conf **confs, const char *ca_dir)
{
	int a=0;
	const char *args[12];
	char *path=NULL;
	struct stat statp;
	const char *ca_burp_ca=get_string(confs[OPT_CA_BURP_CA]);
	const char *ssl_dhfile=get_string(confs[OPT_SSL_DHFILE]);
	if(!lstat(ssl_dhfile, &statp))
	{
		free(path);
		return 0;
	}

	setup_stuff_done++;

	logp("Creating %s\n", ssl_dhfile);
	logp("Running '%s --dhfile %s --dir %s'\n",
		ca_burp_ca, ssl_dhfile, ca_dir);
	a=0;
	args[a++]=ca_burp_ca;
	args[a++]="--dhfile";
	args[a++]=ssl_dhfile;
	args[a++]="--dir";
	args[a++]=ca_dir;
	args[a++]=NULL;
	if(run_script(NULL /* no async yet */, args, NULL, confs, 1 /* wait */,
		0, 0 /* do not use logp - stupid openssl prints lots of dots
		        one at a time with no way to turn it off */))
	{
		logp("Error running %s\n", ca_burp_ca);
		free(path);
		return -1;
	}

	free(path);
	return 0;
}

int ca_server_setup(struct conf **confs)
{
	int ret=0;
	char *ca_dir=NULL;
	const char *ca_conf=get_string(confs[OPT_CA_CONF]);

	if(!ca_conf) return 0;

	/* Need to read CA_DIR from ca_conf. */
	if(!(ca_dir=get_ca_dir(confs)))
	{
		ret=-1;
		goto end;
	}

	if(maybe_make_dhfile(confs, ca_dir))
	{
		ret=-1;
		goto end;
	}

	if(burp_ca_init(confs, ca_dir))
	{
		recursive_delete(ca_dir, "", 1);
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

static int csr_done=0;

// Return 0 for everything OK, signed and returned, -1 for error.
static int sign_client_cert(struct asfd *asfd,
	const char *client, struct conf **confs)
{
	int a=0;
	int ret=-1;
	char msg[256]="";
	char csrpath[512]="";
	char crtpath[512]="";
	struct stat statp;
	const char *args[15];
	csr_done=0;
	const char *ca_name=get_string(confs[OPT_CA_NAME]);
	const char *ca_conf=get_string(confs[OPT_CA_CONF]);
	const char *ca_burp_ca=get_string(confs[OPT_CA_BURP_CA]);
	const char *ca_server_name=get_string(confs[OPT_CA_SERVER_NAME]);
	const char *ssl_cert_ca=get_string(confs[OPT_SSL_CERT_CA]);
	snprintf(csrpath, sizeof(csrpath), "%s/%s.csr", gca_dir, client);
	snprintf(crtpath, sizeof(crtpath), "%s/%s.crt", gca_dir, client);

	if(!strcmp(client, ca_name))
	{
		char msg[512]="";
		snprintf(msg, sizeof(msg), "Will not accept a client certificate request with the same name as the CA (%s)!", ca_name);
		log_and_send(asfd, msg);
		// Do not goto end, as it will delete things;
		return -1;
	}

	if(!lstat(crtpath, &statp))
	{
		char msg[512]="";
		snprintf(msg, sizeof(msg), "Will not accept a client certificate request for '%s' - %s already exists!", client, crtpath);
		log_and_send(asfd, msg);
		// Do not goto end, as it will delete things;
		return -1;
	}

	if(!lstat(csrpath, &statp))
	{
		char msg[512]="";
		snprintf(msg, sizeof(msg), "Will not accept a client certificate request for '%s' - %s already exists!", client, csrpath);
		log_and_send(asfd, msg);
		// Do not goto end, as it will delete things;
		return -1;
	}

	// Tell the client that we will do it, and send the server name at the
	// same time.
	snprintf(msg, sizeof(msg), "csr ok:%s", ca_server_name);
	if(asfd->write_str(asfd, CMD_GEN, msg))
	{
		// Do not goto end, as it will delete things;
		return -1;
	}

	/* After this point, we might have uploaded files, so on error, go
	   to end and delete any new files. */

	// Get the CSR from the client.
	if(receive_a_file(asfd, csrpath, confs)) goto end;

	// Now, sign it.
	logp("Signing certificate signing request from %s\n", client);
	logp("Running '%s --name %s --ca %s --sign --batch --dir %s --config %s'\n", ca_burp_ca, client, ca_name, gca_dir, ca_conf);
	a=0;
	args[a++]=ca_burp_ca;
	args[a++]="--name";
	args[a++]=client;
	args[a++]="--ca";
	args[a++]=ca_name;
	args[a++]="--sign";
	args[a++]="--batch";
	args[a++]="--dir";
	args[a++]=gca_dir;
	args[a++]="--config";
	args[a++]=ca_conf;
	args[a++]=NULL;
	if(run_script(asfd, args, NULL, confs, 1 /* wait */,
		0, 0 /* do not use logp - stupid openssl prints lots of dots
		        one at a time with no way to turn it off */))
	{
		logp("Error running %s\n", ca_burp_ca);
		goto end;
	}

	// Now, we should have a signed certificate.
	// Need to send it back to the client.
	if(send_a_file(asfd, crtpath, confs))
		goto end;

	// Also need to send the CA public certificate back to the client.
	if(send_a_file(asfd, ssl_cert_ca, confs))
		goto end;

	ret=0;
	csr_done++;
end:
	if(ret<0)
	{
		unlink(crtpath);
		unlink(csrpath);
	}
	return ret;
}

static enum asl_ret csr_server_func(struct asfd *asfd,
	struct conf **confs, void *param)
{
	static const char **client;
	static struct iobuf *rbuf;
	const char *ca_conf=get_string(confs[OPT_CA_CONF]);
	client=(const char **)param;
	rbuf=asfd->rbuf;
	if(!strcmp(rbuf->buf, "csr"))
	{
		// Client wants to sign a certificate.
		logp("Client %s wants a certificate signed\n", *client);
		if(!ca_conf || !gca_dir)
		{
			logp("But server is not configured to sign client certificate requests.\n");
			logp("See option 'ca_conf'.\n");
logp("'%s' '%s'\n", ca_conf, gca_dir);
			asfd->write_str(asfd, CMD_ERROR,
			  "server not configured to sign client certificates");
			return ASL_END_ERROR;
		}
		if(sign_client_cert(asfd, *client, confs))
			return ASL_END_ERROR;
		return ASL_END_OK;
	}
	else if(!strcmp(rbuf->buf, "nocsr"))
	{
		// Client does not want to sign a certificate.
		// No problem, just carry on.
		logp("Client %s does not want a certificate signed\n", *client);
		if(asfd->write_str(asfd, CMD_GEN, "nocsr ok"))
			return ASL_END_ERROR;
		return ASL_END_OK;
	}
	else
	{
		iobuf_log_unexpected(rbuf, __func__);
		return ASL_END_ERROR;
	}
}

/* Return 1 for everything OK, signed and returned, -1 for error, 0 for
   nothing done. */
int ca_server_maybe_sign_client_cert(struct asfd *asfd,
	struct conf **confs, struct conf **cconfs)
{
	long min_ver=0;
	long cli_ver=0;
	const char *cname=get_string(cconfs[OPT_CNAME]);

	if((min_ver=version_to_long("1.3.2"))<0
	 || (cli_ver=version_to_long(get_string(cconfs[OPT_PEER_VERSION])))<0)
		return -1;
	// Clients before 1.3.2 did not know how to send cert signing requests.
	if(cli_ver<min_ver) return 0;

	if(asfd->simple_loop(asfd, confs, &cname, __func__,
		csr_server_func)) return -1;
	return csr_done;
}
