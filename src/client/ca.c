#include "include.h"

static int generate_key_and_csr(struct config *conf, const char *csr_path)
{
	int a=0;
	const char *args[12];
	logp("Generating SSL key and certificate signing request\n");
	logp("Running '%s --key --keypath %s --request --requestpath %s --name %s'\n", conf->ca_burp_ca, conf->ssl_key, csr_path, conf->cname);
#ifdef HAVE_WIN32
	win32_enable_backup_privileges();
#endif
	args[a++]=conf->ca_burp_ca;
	args[a++]="--key";
	args[a++]="--keypath";
	args[a++]=conf->ssl_key;
	args[a++]="--request";
	args[a++]="--requestpath";
	args[a++]=csr_path;
	args[a++]="--name";
	args[a++]=conf->cname;
	args[a++]=NULL;
	if(run_script(args, NULL, 0, NULL /* cntr */, 1 /* wait */,
		0 /* do not use logp - stupid openssl prints lots of dots
		     one at a time with no way to turn it off */))
	{
		logp("error when running '%s --key --keypath %s --request --requestpath %s --name %s'\n",
		  conf->ca_burp_ca, conf->ssl_key, csr_path, conf->cname);
		return -1;
	}

	return 0;
}

/* Rewrite the config file with the ssl_peer_cn value changed to what the
   server told us it should be. */
static int rewrite_client_conf(struct config *conf)
{
	int ret=-1;
	char p[32]="";
	FILE *dp=NULL;
	FILE *sp=NULL;
	char *tmp=NULL;
	char buf[4096]="";

	logp("Rewriting config file: %s\n", conf->configfile);
	snprintf(p, sizeof(p), ".%d", getpid());
	if(!(tmp=prepend(conf->configfile, p, strlen(p), "")))
		goto end;
	if(!(sp=open_file(conf->configfile, "rb"))
	  || !(dp=open_file(tmp, "wb")))
		goto end;

	while(fgets(buf, sizeof(buf), sp))
	{
		char *copy=NULL;
		char *field=NULL;
		char *value=NULL;

		if(!(copy=strdup(buf)))
		{
			log_out_of_memory(__FUNCTION__);
			goto end;
		}
		if(config_get_pair(buf, &field, &value)
		  || !field || !value
		  || strcmp(field, "ssl_peer_cn"))
		{
			fprintf(dp, "%s", copy);
			free(copy);
			continue;
		}
		free(copy);
#ifdef HAVE_WIN32
		fprintf(dp, "ssl_peer_cn = %s\r\n", conf->ssl_peer_cn);
#else
		fprintf(dp, "ssl_peer_cn = %s\n", conf->ssl_peer_cn);
#endif
	}
	close_fp(&sp);
	if(close_fp(&dp))
	{
		logp("error closing %s in rewrite_client_conf\n", tmp);
		ret=-1;
		goto end;
	}
#ifdef HAVE_WIN32
	// Need to delete the destination, or Windows gets upset.
	unlink(conf->configfile);
#endif
	if(do_rename(tmp, conf->configfile)) goto end;

	ret=0;
end:
	close_fp(&sp);
	close_fp(&dp);
	if(ret)
	{
		logp("Rewrite failed\n");
		unlink(tmp);
	}
	if(tmp) free(tmp);
	return ret;
}

/* Return 1 for everything OK, signed and returned, -1 for error, 0 for
   nothing done. */
int ca_client_setup(struct config *conf)
{
	int ret=-1;
	struct stat statp;
	struct iobuf rbuf;
	char csr_path[256]="";
	char ssl_cert_tmp[512]="";
	char ssl_cert_ca_tmp[512]="";

	// Do not continue if we have none of the following things set.
	if(  !conf->ca_burp_ca
	  || !conf->ca_csr_dir
	  || !conf->ssl_cert_ca
	  || !conf->ssl_cert
	  || !conf->ssl_key
	// Do not try to get a new certificate if we already have a
	// key.
	  || !lstat(conf->ssl_key, &statp))
	{
		if(async_write_str(CMD_GEN, "nocsr")
		  || async_read_expect(CMD_GEN, "nocsr ok"))
		{
			logp("problem reading from server nocsr\n");
			return -1;
		}
		logp("nocsr ok\n");
		return 0;
	}

	// Tell the server we want to do a signing request.
	if(async_write_str(CMD_GEN, "csr"))
		return -1;

	iobuf_init(&rbuf);
	if(async_read(&rbuf))
	{
		logp("problem reading from server csr\n");
		goto end;
	}
	if(rbuf.cmd!=CMD_GEN || strncmp(rbuf.buf, "csr ok:", strlen("csr ok:")))
	{
		logp("unexpected command from server: %c:%s\n",
			rbuf.cmd, rbuf.buf);
		goto end;
	}
	// The server appends its name after 'csr ok:'
	if(conf->ssl_peer_cn) free(conf->ssl_peer_cn);
	if(!(conf->ssl_peer_cn=strdup(rbuf.buf+strlen("csr ok:"))))
	{
		log_out_of_memory(__FUNCTION__);
		goto end;
	}

	logp("Server will sign a certificate request\n");

	// First need to generate a client key and a certificate signing
	// request.
	snprintf(csr_path, sizeof(csr_path), "%s/%s.csr",
		conf->ca_csr_dir, conf->cname);
	if(generate_key_and_csr(conf, csr_path)) goto end;

	// Then copy the csr to the server.
	if(send_a_file(csr_path, conf)) goto end;

	snprintf(ssl_cert_tmp, sizeof(ssl_cert_tmp), "%s.%d",
		conf->ssl_cert, getpid());
	snprintf(ssl_cert_ca_tmp, sizeof(ssl_cert_ca_tmp), "%s.%d",
		conf->ssl_cert_ca, getpid());

	// The server will then sign it, and give it back.
	if(receive_a_file(ssl_cert_tmp, conf)) goto end;

	// The server will also send the CA certificate.
	if(receive_a_file(ssl_cert_ca_tmp, conf)) goto end;

	if(do_rename(ssl_cert_tmp, conf->ssl_cert)
	  || do_rename(ssl_cert_ca_tmp, conf->ssl_cert_ca))
		goto end;

	// Need to rewrite our configuration file to contain the server
	// name (ssl_peer_cn)
	if(rewrite_client_conf(conf)) goto end;

	// My goodness, everything seems to have gone OK. Stand back!
	ret=1;
end:
	if(rbuf.buf) free(rbuf.buf);
	if(ret<0)
	{
		// On error, remove any possibly newly created files, so that
		// this function might run again on another go.
		unlink(csr_path);
		unlink(conf->ssl_key);
		unlink(conf->ssl_cert);
		unlink(conf->ssl_cert_ca);
		unlink(ssl_cert_tmp);
		unlink(ssl_cert_ca_tmp);
	}
	return ret;
}
