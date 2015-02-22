#include "include.h"
#include "../cmd.h"

static int generate_key_and_csr(struct asfd *asfd,
	struct conf **confs, const char *csr_path)
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
	if(run_script(asfd, args, NULL, conf, 1 /* wait */,
		0, 0 /* do not use logp - stupid openssl prints lots of dots
		        one at a time with no way to turn it off */))
	{
		logp("error when running '%s --key --keypath %s --request --requestpath %s --name %s'\n",
		  conf->ca_burp_ca, conf->ssl_key, csr_path, conf->cname);
		return -1;
	}

	return 0;
}

/* Rewrite the conf file with the ssl_peer_cn value changed to what the
   server told us it should be. */
static int rewrite_client_conf(struct conf **confs)
{
	int ret=-1;
	char p[32]="";
	FILE *dp=NULL;
	FILE *sp=NULL;
	char *tmp=NULL;
	char buf[4096]="";

	logp("Rewriting conf file: %s\n", conf->conffile);
	snprintf(p, sizeof(p), ".%d", getpid());
	if(!(tmp=prepend(conf->conffile, p, strlen(p), "")))
		goto end;
	if(!(sp=open_file(conf->conffile, "rb"))
	  || !(dp=open_file(tmp, "wb")))
		goto end;

	while(fgets(buf, sizeof(buf), sp))
	{
		char *copy=NULL;
		char *field=NULL;
		char *value=NULL;

		if(!(copy=strdup_w(buf, __func__)))
			goto end;
		if(conf_get_pair(buf, &field, &value)
		  || !field || !value
		  || strcmp(field, "ssl_peer_cn"))
		{
			fprintf(dp, "%s", copy);
			free_w(&copy);
			continue;
		}
		free_w(&copy);
#ifdef HAVE_WIN32
		fprintf(dp, "ssl_peer_cn = %s\r\n", conf->ssl_peer_cn);
#else
		fprintf(dp, "ssl_peer_cn = %s\n", conf->ssl_peer_cn);
#endif
	}
	close_fp(&sp);
	if(close_fp(&dp))
	{
		logp("error closing %s in %s\n", tmp, __func__);
		goto end;
	}
	// Nasty race conditions going on here. However, the new config
	// file will get left behind, so at worse you will have to move
	// the new file into the correct place by hand. Or delete everything
	// and start again.
#ifdef HAVE_WIN32
	// Need to delete the destination, or Windows gets upset.
	unlink(conf->conffile);
#endif
	if(do_rename(tmp, conf->conffile)) goto end;

	ret=0;
end:
	close_fp(&sp);
	close_fp(&dp);
	if(ret)
	{
		logp("Rewrite failed\n");
		unlink(tmp);
	}
	free_w(&tmp);
	return ret;
}

static enum asl_ret csr_client_func(struct asfd *asfd,
        struct conf **confs, void *param)
{
	if(strncmp_w(asfd->rbuf->buf, "csr ok:"))
	{
		iobuf_log_unexpected(asfd->rbuf, __func__);
		return ASL_END_ERROR;
	}
	// The server appends its name after 'csr ok:'
	free_w(&conf->ssl_peer_cn);
	if(!(conf->ssl_peer_cn
		=strdup_w(asfd->rbuf->buf+strlen("csr ok:"), __func__)))
			return ASL_END_ERROR;
	return ASL_END_OK;
}

/* Return 1 for everything OK, signed and returned, -1 for error, 0 for
   nothing done. */
int ca_client_setup(struct asfd *asfd, struct conf **confs)
{
	int ret=-1;
	struct stat statp;
	char csr_path[256]="";
	char ssl_cert_tmp[512]="";
	char ssl_cert_ca_tmp[512]="";

	// Do not continue if we have one of the following things not set.
	if(  !conf->ca_burp_ca
	  || !conf->ca_csr_dir
	  || !conf->ssl_cert_ca
	  || !conf->ssl_cert
	  || !conf->ssl_key
	// Do not try to get a new certificate if we already have a key.
	  || !lstat(conf->ssl_key, &statp))
	{
		if(asfd->write_str(asfd, CMD_GEN, "nocsr")
		  || asfd->read_expect(asfd, CMD_GEN, "nocsr ok"))
		{
			logp("problem reading from server nocsr\n");
			goto end;
		}
		logp("nocsr ok\n");
		ret=0;
		goto end;
	}

	// Tell the server we want to do a signing request.
	if(asfd->write_str(asfd, CMD_GEN, "csr")
	  || asfd->simple_loop(asfd, conf, NULL, __func__, csr_client_func))
		goto end;

	logp("Server will sign a certificate request\n");

	// First need to generate a client key and a certificate signing
	// request.
	snprintf(csr_path, sizeof(csr_path), "%s/%s.csr",
		conf->ca_csr_dir, conf->cname);
	if(generate_key_and_csr(asfd, conf, csr_path)) goto end_cleanup;

	// Then copy the csr to the server.
	if(send_a_file(asfd, csr_path, conf)) goto end_cleanup;

	snprintf(ssl_cert_tmp, sizeof(ssl_cert_tmp), "%s.%d",
		conf->ssl_cert, getpid());
	snprintf(ssl_cert_ca_tmp, sizeof(ssl_cert_ca_tmp), "%s.%d",
		conf->ssl_cert_ca, getpid());

	// The server will then sign it, and give it back.
	if(receive_a_file(asfd, ssl_cert_tmp, conf)) goto end_cleanup;

	// The server will also send the CA certificate.
	if(receive_a_file(asfd, ssl_cert_ca_tmp, conf)) goto end_cleanup;

	// Possible race condition - the rename can delete the destination
	// and then fail. Worse case, the user has to rename them by hand.
	if(do_rename(ssl_cert_tmp, conf->ssl_cert)
	  || do_rename(ssl_cert_ca_tmp, conf->ssl_cert_ca))
		goto end_cleanup;

	// Need to rewrite our configuration file to contain the server
	// name (ssl_peer_cn)
	if(rewrite_client_conf(conf)) goto end_cleanup;

	// My goodness, everything seems to have gone OK. Stand back!
	ret=1;
end_cleanup:
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
end:
	return ret;
}
