#include "../burp.h"
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
#include "cvss.h"
#include "ca.h"

static int generate_key_and_csr(struct asfd *asfd,
	struct conf **confs, const char *csr_path)
{
	int a=0;
	const char *args[12];
	const char *ca_burp_ca=get_string(confs[OPT_CA_BURP_CA]);
	const char *cname=get_string(confs[OPT_CNAME]);
	const char *ssl_key=get_string(confs[OPT_SSL_KEY]);

	logp("Generating SSL key and certificate signing request\n");
	logp("Running '%s --key --keypath %s --request --requestpath %s --name %s'\n", ca_burp_ca, ssl_key, csr_path, cname);
#ifdef HAVE_WIN32
	win32_enable_backup_privileges();
#else
	// FIX THIS
	signal(SIGPIPE, SIG_IGN);
#endif
	args[a++]=ca_burp_ca;
	args[a++]="--key";
	args[a++]="--keypath";
	args[a++]=ssl_key;
	args[a++]="--request";
	args[a++]="--requestpath";
	args[a++]=csr_path;
	args[a++]="--name";
	args[a++]=cname;
	args[a++]=NULL;
	if(run_script(asfd, args, NULL, confs, 1 /* wait */,
		0, 0 /* do not use logp - stupid openssl prints lots of dots
		        one at a time with no way to turn it off */))
	{
		logp("error when running '%s --key --keypath %s --request --requestpath %s --name %s'\n",
			ca_burp_ca, ssl_key, csr_path, cname);
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
	struct fzp *dp=NULL;
	struct fzp *sp=NULL;
	char *tmp=NULL;
	char buf[4096]="";
	const char *conffile=get_string(confs[OPT_CONFFILE]);
	const char *ssl_peer_cn=get_string(confs[OPT_SSL_PEER_CN]);

	snprintf(p, sizeof(p), ".%d", getpid());
	if(!(tmp=prepend(conffile, p)))
		goto end;
	if(!(sp=fzp_open(conffile, "rb"))
	  || !(dp=fzp_open(tmp, "wb")))
		goto end;

	while(fzp_gets(sp, buf, sizeof(buf)))
	{
		char *copy=NULL;
		char *field=NULL;
		char *value=NULL;
		int r=0;

		if(!(copy=strdup_w(buf, __func__)))
			goto end;
		if(conf_get_pair(buf, &field, &value, &r)
		  || !field || !value
		  || strcmp(field, "ssl_peer_cn"))
		{
			fzp_printf(dp, "%s", copy);
			free_w(&copy);
			continue;
		}
		free_w(&copy);
#ifdef HAVE_WIN32
		fzp_printf(dp, "ssl_peer_cn = %s\r\n", ssl_peer_cn);
#else
		fzp_printf(dp, "ssl_peer_cn = %s\n", ssl_peer_cn);
#endif
	}
	fzp_close(&sp);
	if(fzp_close(&dp))
	{
		logp("error closing %s in %s\n", tmp, __func__);
		goto end;
	}

	if(files_equal(conffile, tmp, 0/*compressed*/))
	{
		// No need to overwrite if there were no differences.
		ret=0;
		unlink(tmp);
		goto end;
	}

	logp("Rewriting conf file: %s\n", conffile);

	// Nasty race conditions going on here. However, the new config
	// file will get left behind, so at worse you will have to move
	// the new file into the correct place by hand. Or delete everything
	// and start again.
#ifdef HAVE_WIN32
	// Need to delete the destination, or Windows gets upset.
	unlink(conffile);
#endif
	if(do_rename(tmp, conffile)) goto end;

	ret=0;
end:
	fzp_close(&sp);
	fzp_close(&dp);
	if(ret)
	{
		logp("%s with %s failed\n", __func__, conffile);
		unlink(tmp);
	}
	free_w(&tmp);
	return ret;
}

static enum asl_ret csr_client_func(struct asfd *asfd,
        struct conf **confs, __attribute__((unused)) void *param)
{
	if(strncmp_w(asfd->rbuf->buf, "csr ok:"))
	{
		iobuf_log_unexpected(asfd->rbuf, __func__);
		return ASL_END_ERROR;
	}
	// The server appends its name after 'csr ok:'
	if(set_string(confs[OPT_SSL_PEER_CN], 
		asfd->rbuf->buf+strlen("csr ok:")))
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
	const char *ca_burp_ca=get_string(confs[OPT_CA_BURP_CA]);
	const char *ca_csr_dir=get_string(confs[OPT_CA_CSR_DIR]);
	const char *cname=get_string(confs[OPT_CNAME]);
	const char *ssl_key=get_string(confs[OPT_SSL_KEY]);
	const char *ssl_cert=get_string(confs[OPT_SSL_CERT]);
	const char *ssl_cert_ca=get_string(confs[OPT_SSL_CERT_CA]);
	struct cntr *cntr=get_cntr(confs);

	/* Store setting, compared later to decide whether to rewrite the config */
	char *ssl_peer_cn_old=strdup_w(get_string(confs[OPT_SSL_PEER_CN]), __func__);
	if(!ssl_peer_cn_old) goto end;

	// Do not continue if we have one of the following things not set.
	if(  !ca_burp_ca
	  || !ca_csr_dir
	  || !ssl_cert_ca
	  || !ssl_cert
	  || !ssl_key
	// Do not try to get a new certificate if we already have a key.
	  || !lstat(ssl_key, &statp))
	{
		if(asfd->write_str(asfd, CMD_GEN, "nocsr")
		  || asfd_read_expect(asfd, CMD_GEN, "nocsr ok"))
		{
			logp("problem reading from server nocsr\n");
			goto end;
		}
		logp("nocsr ok\n");
		ret=0;
		goto end;
	}

	// Tell the server we want to do a signing request and store the servers name in ssl_peer_cn.
	if(asfd->write_str(asfd, CMD_GEN, "csr")
	  || asfd->simple_loop(asfd, confs, NULL, __func__, csr_client_func))
		goto end;

	logp("Server will sign a certificate request\n");

	// First need to generate a client key and a certificate signing
	// request.
	snprintf(csr_path, sizeof(csr_path), "%s/%s.csr", ca_csr_dir, cname);
	if(generate_key_and_csr(asfd, confs, csr_path)) goto end_cleanup;

	// Then copy the csr to the server.
	if(send_a_file(asfd, csr_path, cntr)) goto end_cleanup;

	snprintf(ssl_cert_tmp, sizeof(ssl_cert_tmp), "%s.%d",
		ssl_cert, getpid());
	snprintf(ssl_cert_ca_tmp, sizeof(ssl_cert_ca_tmp), "%s.%d",
		ssl_cert_ca, getpid());

	// The server will then sign it, and give it back.
	if(receive_a_file(asfd, ssl_cert_tmp, cntr)) goto end_cleanup;

	// The server will also send the CA certificate.
	if(receive_a_file(asfd, ssl_cert_ca_tmp, cntr)) goto end_cleanup;

	// Possible race condition - the rename can delete the destination
	// and then fail. Worse case, the user has to rename them by hand.
	if(do_rename(ssl_cert_tmp, ssl_cert)
	  || do_rename(ssl_cert_ca_tmp, ssl_cert_ca))
		goto end_cleanup;

	// Need to rewrite our configuration file to contain the server
	// name (ssl_peer_cn) if the name differs from the config file.
	if(strncmp_w(ssl_peer_cn_old, get_string(confs[OPT_SSL_PEER_CN])))
	{
	    if(rewrite_client_conf(confs)) goto end_cleanup;
	}

	// My goodness, everything seems to have gone OK. Stand back!
	ret=1;
end_cleanup:
	if(ret<0)
	{
		// On error, remove any possibly newly created files, so that
		// this function might run again on another go.
		unlink(csr_path);
		unlink(ssl_key);
		unlink(ssl_cert);
		unlink(ssl_cert_ca);
		unlink(ssl_cert_tmp);
		unlink(ssl_cert_ca_tmp);
	}
end:
	if(ssl_peer_cn_old) free_w(&ssl_peer_cn_old);
	return ret;
}
