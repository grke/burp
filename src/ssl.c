#include "burp.h"
#include "conf.h"
#include "log.h"

static BIO *bio_err=0;
static const char *pass=NULL;

SSL_CTX *berr_exit(const char *string)
{
	BIO_printf(bio_err, "%s\n", string);
	ERR_print_errors(bio_err);
	return NULL;
}

int ssl_load_dh_params(SSL_CTX *ctx, struct config *conf)
{
	DH *ret=0;
	BIO *bio=NULL;

	if(!(bio=BIO_new_file(conf->ssl_dhfile, "r")))
	{
		berr_exit("Couldn't open DH file");
		return -1;
	}

	ret=PEM_read_bio_DHparams(bio, NULL, NULL, NULL);
	BIO_free(bio);
	if(SSL_CTX_set_tmp_dh(ctx, ret)<0)
	{
		berr_exit("Couldn't set DH parameters");
		return -1;
	}
	return 0;
}

/*The password code is not thread safe*/
static int password_cb(char *buf, int num, int rwflag, void *userdata)
{
	if(num<(int)strlen(pass)+1) return 0;
	strcpy(buf, pass);
	return strlen(pass);
}

void ssl_load_globals(void)
{
	if(!bio_err)
	{
		/* Global system initialization*/
		SSL_library_init();
		SSL_load_error_strings();

		/* An error write context */
		bio_err=BIO_new_fp(stderr, BIO_NOCLOSE);
	}
}

SSL_CTX *ssl_initialise_ctx(struct config *conf)
{
	SSL_CTX *ctx=NULL;
	SSL_METHOD *meth=NULL;
	char *ssl_key=NULL;

	/* Create our context*/
	meth=(SSL_METHOD *)SSLv23_method();
	ctx=(SSL_CTX *)SSL_CTX_new(meth);

	/* Load our keys and certificates*/
	if(!(SSL_CTX_use_certificate_chain_file(ctx, conf->ssl_cert)))
		return berr_exit("Can't read certificate file");

	pass=conf->ssl_key_password;
	SSL_CTX_set_default_passwd_cb(ctx, password_cb);

	if(conf->ssl_key)
		ssl_key=conf->ssl_key;
	else
		ssl_key=conf->ssl_cert;

	if(!(SSL_CTX_use_PrivateKey_file(ctx,ssl_key,SSL_FILETYPE_PEM)))
		return berr_exit("Can't read key file");

	/* Load the CAs we trust*/
	if(!(SSL_CTX_load_verify_locations(ctx, conf->ssl_cert_ca, 0)))
		return berr_exit("Can't read CA list");

	return ctx;
}

void ssl_destroy_ctx(SSL_CTX *ctx)
{
	SSL_CTX_free(ctx);
}

#ifndef HAVE_WIN32
static void sanitise(char *buf)
{
	char *cp=NULL;
	for(cp=buf; *cp; cp++)
	{
		if(!isalnum(*cp)
		  && !isblank(*cp)
		  && *cp!='_'
		  && *cp!='-'
		  && *cp!='.'
		  && *cp!='@')
			*cp='_';
	}
}
#endif

int ssl_check_cert(SSL *ssl, struct config *conf)
{
	X509 *peer;
	char tmpbuf[256];

	if(!conf->ssl_peer_cn)
	{
		logp("ssl_peer_cn not set.\n");
		return -1;
	}

	if(!(peer=SSL_get_peer_certificate(ssl)))
	{
		logp("Could not get peer certificate.\n");
		return -1;
	}
	if(SSL_get_verify_result(ssl)!=X509_V_OK)
	{
		berr_exit("Certificate doesn't verify");
		return -1;
	}

	X509_NAME_get_text_by_NID(X509_get_subject_name(peer),
		NID_commonName, tmpbuf, sizeof(tmpbuf));
	if(strcasecmp(tmpbuf, conf->ssl_peer_cn))
	{
		logp("cert common name doesn't match configured ssl_peer_cn\n");
		logp("'%s'!='%s'\n", tmpbuf, conf->ssl_peer_cn);
		return -1;
	}

#ifndef HAVE_WIN32
	sanitise(tmpbuf);
	setenv("X509_PEER_CN", tmpbuf, 1);
	X509_NAME_get_text_by_NID(X509_get_issuer_name(peer),
		NID_commonName, tmpbuf, sizeof(tmpbuf));
	sanitise(tmpbuf);
	setenv("X509_PEER_IN", tmpbuf, 1);
#endif

	return 0;
}
