#include "../burp.h"
#include "../alloc.h"
#include "../asfd.h"
#include "../async.h"
#include "../cmd.h"
#include "../conf.h"
#include "../conffile.h"
#include "../fsops.h"
#include "../handy.h"
#include "../iobuf.h"
#include "../log.h"
#include "../run_script.h"
#include "auth.h"
#include "ca.h"

static int setup_stuff_done=0;

static char *get_ca_dir(const char *ca_conf)
{
	struct fzp *fzp=NULL;
	char buf[4096]="";
	char *ca_dir=NULL;
	int r=0;

	if(!(fzp=fzp_open(ca_conf, "r")))
		goto end;
	while(fzp_gets(fzp, buf, sizeof(buf)))
	{
		char *field=NULL;
		char *value=NULL;
		if(conf_get_pair(buf, &field, &value, &r)
		  || !field || !value) continue;

		if(!strcasecmp(field, "CA_DIR"))
		{
			if(!(ca_dir=strdup_w(value, __func__)))
				goto end;
			break;
		}
	}
end:
	fzp_close(&fzp);
	return ca_dir;
}

static char *get_generated_crl_path(const char *ca_dir, const char *ca_name)
{
	int flen=0;
	char *fname=NULL;
	char *crl_path=NULL;

	flen+=strlen(ca_name);
	flen+=strlen("CA_");
	flen+=strlen(".crl")+1;
	if(!(fname=(char *)malloc_w(flen, __func__)))
		goto end;
	snprintf(fname, flen, "CA_%s.crl", ca_name);
	crl_path=prepend_s(ca_dir, fname);
end:
	free_w(&fname);
	return crl_path;
}

static char *get_crl_path(struct conf **confs,
	const char *ca_dir, const char *ca_name)
{
	char *crl_path;
	// If the conf told us the path, use it.
	if((crl_path=get_string(confs[OPT_CA_CRL])))
		return strdup_w(crl_path, __func__);

	// Otherwise, build it ourselves.
	return get_generated_crl_path(ca_dir, ca_name);
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

static int ca_init(struct conf **confs, const char *ca_dir)
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

	if(is_dir_lstat(ca_dir)>0) return 0;

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
	struct stat statp;
	const char *ca_burp_ca=get_string(confs[OPT_CA_BURP_CA]);
	const char *ssl_dhfile=get_string(confs[OPT_SSL_DHFILE]);
	if(!lstat(ssl_dhfile, &statp))
		return 0;

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
		return -1;
	}

	return 0;
}

static int maybe_make_crl(struct conf **confs, const char *ca_dir,
	const char *ca_conf)
{
	int a=0;
	int ret=-1;
	const char *args[12];
	struct stat statp;
	char *crl_path=NULL;
	const char *ca_name=get_string(confs[OPT_CA_NAME]);
	const char *ca_burp_ca=get_string(confs[OPT_CA_BURP_CA]);
	if(!ca_conf || !*ca_conf
	  || !ca_burp_ca || !*ca_burp_ca
	  || !ca_name || !*ca_name)
		return 0;
	if(!(crl_path=get_crl_path(confs, ca_dir, ca_name)))
		goto end;
	if(!lstat(crl_path, &statp))
	{
		ret=0;
		goto end;
	}
	// Create it even if we are not going to use it because of
	// OPT_CA_CRL_CHECK = 0.

	setup_stuff_done++;

	logp("Creating %s\n", crl_path);
	logp("Running '%s --name %s --config %s --dir %s --crl'\n",
		ca_burp_ca, ca_name, ca_conf, ca_dir);
	a=0;
	args[a++]=ca_burp_ca;
	args[a++]="--name";
	args[a++]=ca_name;
	args[a++]="--config";
	args[a++]=ca_conf;
	args[a++]="--dir";
	args[a++]=ca_dir;
	args[a++]="--crl";
	args[a++]=NULL;
	if(run_script(NULL /* no async yet */, args, NULL, confs, 1 /* wait */,
		0, 0 /* do not use logp - stupid openssl prints lots of dots
		        one at a time with no way to turn it off */))
	{
		logp("Error running %s\n", ca_burp_ca);
		return -1;
	}
	ret=0;
end:
	free_w(&crl_path);
	return ret;
}

int ca_server_setup(struct conf **confs)
{
	int ret=-1;
	char *ca_dir=NULL;
	const char *ca_conf=get_string(confs[OPT_CA_CONF]);

	if(!ca_conf)
	{
		ret=0;
		goto end;
	}

	if(!(ca_dir=get_ca_dir(ca_conf)))
		goto end;

	if(maybe_make_dhfile(confs, ca_dir))
		goto end;

	if(ca_init(confs, ca_dir))
	{
		recursive_delete(ca_dir);
		goto end;
	}

	if(maybe_make_crl(confs, ca_dir, ca_conf))
		goto end;

	ret=0;
end:
	free_w(&ca_dir);
	if(setup_stuff_done)
	{
		if(ret) logp("CA setup failed\n");
		else logp("CA setup succeeded\n");
	}
	return ret;
}

static int check_path_does_not_exist(struct asfd *asfd,
	const char *client, const char *path)
{
	struct stat statp;
	if(!lstat(path, &statp))
	{
		char msg[1024]="";
		snprintf(msg, sizeof(msg), "Will not accept a client certificate request for '%s' - %s already exists!", client, path);
		log_and_send(asfd, msg);
		return -1;
	}
	return 0;
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
	char *ca_dir=NULL;
	const char *args[15];
	csr_done=0;
	const char *ca_name=get_string(confs[OPT_CA_NAME]);
	const char *ca_conf=get_string(confs[OPT_CA_CONF]);
	const char *ca_burp_ca=get_string(confs[OPT_CA_BURP_CA]);
	const char *ca_server_name=get_string(confs[OPT_CA_SERVER_NAME]);
	const char *ssl_cert_ca=get_string(confs[OPT_SSL_CERT_CA]);
	struct cntr *cntr=get_cntr(confs);

	if(!(ca_dir=get_ca_dir(ca_conf)))
		goto error;

	snprintf(csrpath, sizeof(csrpath), "%s/%s.csr", ca_dir, client);
	snprintf(crtpath, sizeof(crtpath), "%s/%s.crt", ca_dir, client);

	if(!strcmp(client, ca_name))
	{
		char msg[512]="";
		snprintf(msg, sizeof(msg), "Will not accept a client certificate request with the same name as the CA (%s)!", ca_name);
		log_and_send(asfd, msg);
		goto error;
	}

	if(check_path_does_not_exist(asfd, client, crtpath)
	  || check_path_does_not_exist(asfd, client, csrpath))
		goto error;

	// Tell the client that we will do it, and send the server name at the
	// same time.
	snprintf(msg, sizeof(msg), "csr ok:%s", ca_server_name);
	if(asfd->write_str(asfd, CMD_GEN, msg))
		goto error;

	/* After this point, we might have uploaded files, so on error, go
	   to end and delete any new files. */

	// Get the CSR from the client.
	if(receive_a_file(asfd, csrpath, cntr))
		goto del_files;

	// Now, sign it.
	logp("Signing certificate signing request from %s\n", client);
	logp("Running '%s --name %s --ca %s --sign --batch --dir %s --config %s'\n", ca_burp_ca, client, ca_name, ca_dir, ca_conf);
	a=0;
	args[a++]=ca_burp_ca;
	args[a++]="--name";
	args[a++]=client;
	args[a++]="--ca";
	args[a++]=ca_name;
	args[a++]="--sign";
	args[a++]="--batch";
	args[a++]="--dir";
	args[a++]=ca_dir;
	args[a++]="--config";
	args[a++]=ca_conf;
	args[a++]=NULL;
	if(run_script(asfd, args, NULL, confs, 1 /* wait */,
		0, 0 /* do not use logp - stupid openssl prints lots of dots
		        one at a time with no way to turn it off */))
	{
		logp("Error running %s\n", ca_burp_ca);
		goto del_files;
	}

	// Now, we should have a signed certificate.
	// Need to send it back to the client.
	if(send_a_file(asfd, crtpath, cntr))
		goto del_files;

	// Also need to send the CA public certificate back to the client.
	if(send_a_file(asfd, ssl_cert_ca, cntr))
		goto del_files;

	ret=0;
	csr_done++;
del_files:
	if(ret<0)
	{
		unlink(crtpath);
		unlink(csrpath);
	}
error:
	free_w(&ca_dir);
	return ret;
}

static enum asl_ret csr_server_func(struct asfd *asfd,
	struct conf **confs, void *param)
{
	struct iobuf *rbuf;
	const char *ca_conf;
	const char **cname;

	rbuf=asfd->rbuf;
	cname=(const char **)param;
	ca_conf=get_string(confs[OPT_CA_CONF]);

	if(!strcmp(rbuf->buf, "csr"))
	{
		// Client wants to sign a certificate.
		logp("Client %s wants a certificate signed\n", *cname);
		if(!ca_conf)
		{
			logp("But server is not configured to sign client certificate requests.\n");
			logp("See option 'ca_conf'.\n");
			asfd->write_str(asfd, CMD_ERROR,
			  "server not configured to sign client certificates");
			return ASL_END_ERROR;
		}
		if(sign_client_cert(asfd, *cname, confs))
			return ASL_END_ERROR;
		return ASL_END_OK;
	}
	else if(!strcmp(rbuf->buf, "nocsr"))
	{
		// Client does not want to sign a certificate.
		// No problem, just carry on.
		logp("Client %s does not want a certificate signed\n", *cname);
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
	const char *cname=NULL;

	if((min_ver=version_to_long("1.3.2"))<0
	 || (cli_ver=version_to_long(get_string(cconfs[OPT_PEER_VERSION])))<0)
		return -1;
	// Clients before 1.3.2 did not know how to send cert signing requests.
	if(cli_ver<min_ver) return 0;

	if(!asfd)
	{
		logp("asfd not set up in %s\n", __func__);
		return -1;
	}

	cname=get_string(cconfs[OPT_CNAME]);

	if(asfd->simple_loop(asfd, confs, &cname, __func__, csr_server_func))
		return -1;

	return csr_done;
}

int ca_x509_verify_crl(struct conf **confs,
	X509 *peer_cert, const char *ssl_peer_cn)
{
	int n;
	int i;
	int ret=-1;
	BIO *in=NULL;
	BIGNUM *bnser=NULL;
	X509_CRL *crl=NULL;
	X509_REVOKED *revoked;
	ASN1_INTEGER *serial=NULL;
	char *crl_path=NULL;
	char *ca_dir=NULL;
	const char *ca_name=get_string(confs[OPT_CA_NAME]);
	const char *ca_conf=get_string(confs[OPT_CA_CONF]);
	int crl_check=get_int(confs[OPT_CA_CRL_CHECK]);

	if(!crl_check)
	{
		ret=0;
		goto end;
	}

	if(!(ca_dir=get_ca_dir(ca_conf)))
		goto end;

	if(!ca_name || !*ca_name  || !ca_dir)
	{
		ret=0;
		goto end;
	}

	if(!(crl_path=get_crl_path(confs, ca_dir, ca_name)))
		goto end;

	if(!(in=BIO_new_file(crl_path, "r")))
	{
		logp("CRL: cannot read: %s\n", crl_path);
		goto end;
	}

	if(!(crl=PEM_read_bio_X509_CRL(in, NULL, NULL, NULL)))
	{
		logp_ssl_err("CRL: cannot read CRL from file %s\n", crl_path);
		goto end;
	}

	if(X509_NAME_cmp(X509_CRL_get_issuer(crl),
		X509_get_issuer_name(peer_cert)))
	{
		logp_ssl_err("CRL: CRL %s is from a different issuer than the issuer of certificate %s\n", crl_path, ssl_peer_cn);
		goto end;
	}

	n=sk_X509_REVOKED_num(X509_CRL_get_REVOKED(crl));
	for(i=0; i<n; i++)
	{
		revoked=(X509_REVOKED *)
			sk_X509_REVOKED_value(X509_CRL_get_REVOKED(crl), i);
		if(!ASN1_INTEGER_cmp(
#if OPENSSL_VERSION_NUMBER < 0x1010000fL || defined(LIBRESSL_VERSION_NUMBER)
			revoked->serialNumber,
#else
			X509_REVOKED_get0_serialNumber(revoked),
#endif
			X509_get_serialNumber(peer_cert)))
		{
			serial=X509_get_serialNumber(peer_cert);
			bnser=ASN1_INTEGER_to_BN(serial, NULL);
			logp_ssl_err("CRL check failed: %s (%s) is revoked\n",
				ssl_peer_cn,
				serial ? BN_bn2hex(bnser):"not available");
			goto end;
		}
	}

	ret=0;
end:
	if(in) BIO_free(in);
	if(crl) X509_CRL_free(crl);
	free_w(&crl_path);
	free_w(&ca_dir);
	return ret;
}
