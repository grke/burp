#include "burp.h"
#include "conf.h"
#include "log.h"

static BIO *bio_err=0;
static const char *pass=NULL;

SSL_CTX *berr_exit(const char *fmt, ...)
{
	char buf[512]="";
	va_list ap;
	va_start(ap, fmt);
	vsnprintf(buf, sizeof(buf), fmt, ap);
	BIO_printf(bio_err, "%s", buf);
	ERR_print_errors(bio_err);
	return NULL;
}

int ssl_load_dh_params(SSL_CTX *ctx, struct config *conf)
{
	DH *ret=0;
	BIO *bio=NULL;

	if(!(bio=BIO_new_file(conf->ssl_dhfile, "r")))
	{
		berr_exit("Couldn't open ssl_dhfile: %s\n", conf->ssl_dhfile);
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

static int ssl_load_keys_and_certs(SSL_CTX *ctx, struct config *conf)
{
	char *ssl_key=NULL;
	struct stat statp;

	/* Load our keys and certificates if the path exists. */
	if(conf->ssl_cert && !lstat(conf->ssl_cert, &statp)
	  && !SSL_CTX_use_certificate_chain_file(ctx, conf->ssl_cert))
	{
		berr_exit("Can't read ssl_cert: %s\n", conf->ssl_cert);
		return -1;
	}

	pass=conf->ssl_key_password;
	SSL_CTX_set_default_passwd_cb(ctx, password_cb);

	if(conf->ssl_key)
		ssl_key=conf->ssl_key;
	else
		ssl_key=conf->ssl_cert;

	/* Load the key file, if the path exists */
	if(ssl_key && !lstat(ssl_key, &statp)
	  && !SSL_CTX_use_PrivateKey_file(ctx,ssl_key,SSL_FILETYPE_PEM))
	{
		berr_exit("Can't read ssl_key file: %s\n", ssl_key);
		return -1;
	}

	/* Load the CAs we trust, if the path exists. */
	if(conf->ssl_cert_ca && !lstat(conf->ssl_cert_ca, &statp)
	  && !SSL_CTX_load_verify_locations(ctx, conf->ssl_cert_ca, 0))
	{
		berr_exit("Can't read ssl_cert_ca file: %s\n",
			conf->ssl_cert_ca);
		return -1;
	}

	return 0;
}

SSL_CTX *ssl_initialise_ctx(struct config *conf)
{
	SSL_CTX *ctx=NULL;
	SSL_METHOD *meth=NULL;

	/* Create our context*/
	meth=(SSL_METHOD *)SSLv23_method();
	ctx=(SSL_CTX *)SSL_CTX_new(meth);

	if(ssl_load_keys_and_certs(ctx, conf)) return NULL;

	if(conf->ssl_ciphers) {
		SSL_CTX_set_cipher_list(ctx, conf->ssl_ciphers);
	}

	SSL_CTX_set_options(ctx, SSL_OP_NO_SSLv2|SSL_OP_NO_SSLv3);

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
		  && *cp!=':'
		  && *cp!='@')
			*cp='_';
	}
}

/* This function taken from openvpn-2.2.1 and tidied up a bit. */
static int setenv_x509(X509_NAME *x509, const char *type)
{
	int i, n;
	int fn_nid;
	ASN1_OBJECT *fn;
	ASN1_STRING *val;
	X509_NAME_ENTRY *ent;
	const char *objbuf;
	unsigned char *buf;
	char *name_expand;
	size_t name_expand_size;

	n = X509_NAME_entry_count (x509);
	for (i = 0; i < n; ++i)
	{
		if(!(ent=X509_NAME_get_entry (x509, i))
		  || !(fn=X509_NAME_ENTRY_get_object(ent))
		  || !(val=X509_NAME_ENTRY_get_data(ent))
		  || (fn_nid=OBJ_obj2nid(fn))==NID_undef
		  || !(objbuf=OBJ_nid2sn(fn_nid)))
			continue;
		buf=(unsigned char *)1; /* bug in OpenSSL 0.9.6b ASN1_STRING_to_UTF8 requires this workaround */
		if(ASN1_STRING_to_UTF8(&buf, val)<=0) continue;
		name_expand_size = 64 + strlen (objbuf);
		if(!(name_expand=(char *)malloc(name_expand_size)))
		{
			log_out_of_memory(__FUNCTION__);
			return -1;
		}
		snprintf(name_expand, name_expand_size,
			"X509_%s_%s", type, objbuf);
		sanitise(name_expand);
		sanitise((char*)buf);
		setenv(name_expand, (char*)buf, 1);
		free (name_expand);
		OPENSSL_free (buf);
	}
	return 0;
}

static int setenv_x509_date(ASN1_TIME *tm, const char *env)
{
	BIO *bio_out=NULL;
	BUF_MEM *bptr=NULL;
	char tmpbuf[256]="";
	if(!(bio_out=BIO_new(BIO_s_mem())))
	{
		log_out_of_memory(__FUNCTION__);
		return -1;
	}
	ASN1_TIME_print(bio_out, tm);
	BIO_get_mem_ptr(bio_out, &bptr);
	BIO_gets(bio_out, tmpbuf, sizeof(tmpbuf)-1);
	BIO_free_all(bio_out);
	sanitise(tmpbuf);
	setenv(env, (char*)tmpbuf, 1);
	return 0;
}

static int setenv_x509_serialnumber(ASN1_INTEGER *i, const char *env)
{
	BIO *bio_out=NULL;
	BUF_MEM *bptr=NULL;
	char tmpbuf[256]="";
	if(!(bio_out=BIO_new(BIO_s_mem())))
	{
		log_out_of_memory(__FUNCTION__);
		return -1;
	}
	i2a_ASN1_INTEGER(bio_out, i);
	BIO_get_mem_ptr(bio_out, &bptr);
	BIO_gets(bio_out, tmpbuf, sizeof(tmpbuf)-1);
	BIO_free_all(bio_out);
	sanitise(tmpbuf);
	setenv(env, (char*)tmpbuf, 1);
	return 0;
}
#endif

int ssl_check_cert(SSL *ssl, struct config *conf)
{
	X509 *peer;
	char tmpbuf[256]="";

	if(!conf->ssl_peer_cn)
	{
		logp("ssl_peer_cn not set.\n");
		return -1;
	}
	SSL_CIPHER_description(SSL_get_current_cipher(ssl),
		tmpbuf, sizeof(tmpbuf));
	logp("SSL is using cipher: %s", tmpbuf);
	if(!(peer=SSL_get_peer_certificate(ssl)))
	{
		logp("Could not get peer certificate.\n");
		return -1;
	}
	if(SSL_get_verify_result(ssl)!=X509_V_OK)
	{
		berr_exit("Certificate doesn't verify.\n");
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
	if(setenv_x509(X509_get_subject_name(peer), "PEER")
	  || setenv_x509(X509_get_issuer_name(peer), "ISSUER"))
		return -1;

	if(setenv_x509_date(X509_get_notBefore(peer), "X509_PEER_NOT_BEFORE")
	  || setenv_x509_date(X509_get_notAfter(peer), "X509_PEER_NOT_AFTER"))
		return -1;

	if(setenv_x509_serialnumber(X509_get_serialNumber(peer),
		"X509_PEER_SERIALNUMBER"))
			return -1;
#endif

	return 0;
}
