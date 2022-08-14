#include "burp.h"
#include "alloc.h"
#include "conf.h"
#include "log.h"
#include "server/ca.h"
#include "ssl.h"

static const char *pass=NULL;

int ssl_do_accept(SSL *ssl)
{
	while(1)
	{
		int r=0;
		int ssl_err;
		ERR_clear_error();
		switch((r=SSL_accept(ssl)))
		{
			case 1:
				return 0;
			case 0:
			default:
				ssl_err=SSL_get_error(ssl, r);
				switch(ssl_err)
				{
					case SSL_ERROR_WANT_READ:
						continue;
					default:
						logp_ssl_err("SSL_accept error: %d\n", ssl_err);
						return -1;
				}
				break;
		}
	}
}

/* Not ready yet
#if OPENSSL_VERSION_NUMBER < 0x30000000L
*/
#if 1
int ssl_load_dh_params(SSL_CTX *ctx, struct conf **confs)
{
	DH *ret=0;
	BIO *bio=NULL;
	const char *ssl_dhfile=get_string(confs[OPT_SSL_DHFILE]);

	if(!(bio=BIO_new_file(ssl_dhfile, "r")))
	{
		logp_ssl_err("Couldn't open ssl_dhfile: %s\n", ssl_dhfile);
		return -1;
	}

	ret=PEM_read_bio_DHparams(bio, NULL, NULL, NULL);
	BIO_free(bio);
	if(SSL_CTX_set_tmp_dh(ctx, ret)<0)
	{
		logp_ssl_err("Couldn't set DH parameters");
		return -1;
	}
	return 0;
}
#else
#include <openssl/decoder.h>
int ssl_load_dh_params(SSL_CTX *ctx, struct conf **confs)
{
	BIO *bio=NULL;
	EVP_PKEY *pkey=NULL;
	OSSL_DECODER_CTX *dctx=NULL;
	const char *ssl_dhfile=get_string(confs[OPT_SSL_DHFILE]);

	if(!(bio=BIO_new_file(ssl_dhfile, "r")))
	{
		logp_ssl_err("Couldn't open ssl_dhfile: %s\n", ssl_dhfile);
		return -1;
	}
	if(!(dctx=OSSL_DECODER_CTX_new_for_pkey(
		&pkey, "PEM", NULL, "DH",
		OSSL_KEYMGMT_SELECT_KEYPAIR,
		NULL, NULL)))
	{
		logp_ssl_err("No suitable decoders found for: %s\n", ssl_dhfile);
		BIO_free(bio);
		OSSL_DECODER_CTX_free(dctx);
		return -1;
	}

	if(!OSSL_DECODER_from_bio(dctx, bio))
	{
		logp_ssl_err("Decoding failure for: %s\n", ssl_dhfile);
		BIO_free(bio);
		OSSL_DECODER_CTX_free(dctx);
		return -1;

	}

	if(SSL_CTX_set_tmp_dh(ctx, pkey)<0)
	{
		logp_ssl_err("Couldn't set DH parameters");
		OSSL_DECODER_CTX_free(dctx);
		return -1;
	}

	OSSL_DECODER_CTX_free(dctx);
	return 0;
}
#endif

static int password_cb(char *buf, int num,
	__attribute__ ((unused)) int rwflag,
	__attribute__ ((unused)) void *userdata)
{
	if(num<(int)strlen(pass)+1) return 0;
	strcpy(buf, pass);
	return strlen(pass);
}

void ssl_load_globals(void)
{
	// Global system initialization.
	SSL_library_init();
	SSL_load_error_strings();
}

static int check_path(const char *path, const char *what)
{
	struct stat statp;
	if(!path) return -1;
	if(stat(path, &statp))
	{
		logp("Could not find %s %s: %s\n",
			what, path, strerror(errno));
		return -1;
	}
	return 0;
}

static int ssl_load_keys_and_certs(SSL_CTX *ctx, struct conf **confs)
{
	char *ssl_key=NULL;
	const char *ssl_cert=get_string(confs[OPT_SSL_CERT]);
	const char *ssl_cert_ca=get_string(confs[OPT_SSL_CERT_CA]);

	// Load our keys and certificates if the path exists.
	if(!check_path(ssl_cert, "ssl_cert")
	  && !SSL_CTX_use_certificate_chain_file(ctx, ssl_cert))
	{
		logp_ssl_err("Can't read ssl_cert: %s\n", ssl_cert);
		return -1;
	}

	pass=get_string(confs[OPT_SSL_KEY_PASSWORD]);
	SSL_CTX_set_default_passwd_cb(ctx, password_cb);

	ssl_key=get_string(confs[OPT_SSL_KEY]);
	if(!ssl_key) ssl_key=get_string(confs[OPT_SSL_CERT]);

	// Load the key file, if the path exists.
	if(!check_path(ssl_key, "ssl_key")
	  && !SSL_CTX_use_PrivateKey_file(ctx, ssl_key, SSL_FILETYPE_PEM))
	{
		logp_ssl_err("Can't read ssl_key file: %s\n", ssl_key);
		return -1;
	}

	// Load the CAs we trust, if the path exists.
	if(!check_path(ssl_cert_ca, "ssl_cert_ca")
	  && !SSL_CTX_load_verify_locations(ctx, ssl_cert_ca, 0))
	{
		logp_ssl_err("Can't read ssl_cert_ca file: %s\n", ssl_cert_ca);
		return -1;
	}

	return 0;
}

SSL_CTX *ssl_initialise_ctx(struct conf **confs)
{
	SSL_CTX *ctx=NULL;
	SSL_METHOD *meth=NULL;
	const char *ssl_ciphers=get_string(confs[OPT_SSL_CIPHERS]);

	// Create our context.
	meth=(SSL_METHOD *)SSLv23_method();
	ctx=(SSL_CTX *)SSL_CTX_new(meth);

	if(ssl_load_keys_and_certs(ctx, confs)) return NULL;

	if(ssl_ciphers)
		SSL_CTX_set_cipher_list(ctx, ssl_ciphers);

	// Unclear what is negotiated, so keep quiet until I figure that out.
	if(!get_int(confs[OPT_SSL_COMPRESSION]))
	{
#ifdef SSL_OP_NO_COMPRESSION
		SSL_CTX_set_options(ctx, SSL_OP_NO_COMPRESSION);
#else
		logp("This version of openssl has no SSL_OP_NO_COMPRESSION option, so turning off config option '%s' will not work. You should probably upgrade openssl.\n", confs[OPT_SSL_COMPRESSION]->field);
#endif
	}
	// Default is zlib5, which needs no option set.

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

// This function taken from openvpn-2.2.1 and tidied up a bit.
static int setenv_x509(X509_NAME *x509, const char *type)
{
	int i, n;
	int fn_nid;
	ASN1_OBJECT *fn;
	ASN1_STRING *val;
	X509_NAME_ENTRY *ent;
	const char *objbuf;
	uint8_t *buf;
	char *name_expand;
	size_t name_expand_size;

	n=X509_NAME_entry_count (x509);
	for(i=0; i<n; ++i)
	{
		if(!(ent=X509_NAME_get_entry (x509, i))
		  || !(fn=X509_NAME_ENTRY_get_object(ent))
		  || !(val=X509_NAME_ENTRY_get_data(ent))
		  || (fn_nid=OBJ_obj2nid(fn))==NID_undef
		  || !(objbuf=OBJ_nid2sn(fn_nid)))
			continue;
		buf=(uint8_t *)1; /* bug in OpenSSL 0.9.6b ASN1_STRING_to_UTF8 requires this workaround */
		if(ASN1_STRING_to_UTF8(&buf, val)<=0) continue;
		name_expand_size=64+strlen(objbuf);
		if(!(name_expand=(char *)malloc_w(name_expand_size, __func__)))
			return -1;
		snprintf(name_expand, name_expand_size,
			"X509_%s_%s", type, objbuf);
		sanitise(name_expand);
		sanitise((char*)buf);
		setenv(name_expand, (char*)buf, 1);
		free_w(&name_expand);
		OPENSSL_free(buf);
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
		log_out_of_memory(__func__);
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
		log_out_of_memory(__func__);
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

int ssl_check_cert(SSL *ssl, struct conf **confs, struct conf **cconfs)
{
	X509 *peer;
	int result;
	char tmpbuf[256]="";
	const char *ssl_peer_cn=get_string(cconfs[OPT_SSL_PEER_CN]);

	if(!ssl_peer_cn)
	{
		logp("ssl_peer_cn not set.\n");
		return -1;
	}

	SSL_CIPHER_description(SSL_get_current_cipher(ssl),
		tmpbuf, sizeof(tmpbuf));
	logp("SSL is using cipher: %s\n", tmpbuf);
	if(!(peer=SSL_get_peer_certificate(ssl)))
	{
		logp("Could not get peer certificate.\n");
		return -1;
	}
	result=SSL_get_verify_result(ssl);
	if(result!=X509_V_OK)
	{
		logp_ssl_err("Certificate doesn't verify (%d).\n", result);
		return -1;
	}

	X509_NAME_get_text_by_NID(X509_get_subject_name(peer),
		NID_commonName, tmpbuf, sizeof(tmpbuf));
	if(strcasecmp(tmpbuf, ssl_peer_cn))
	{
		logp("cert common name doesn't match configured ssl_peer_cn\n");
		logp("'%s'!='%s'\n", tmpbuf, ssl_peer_cn);
		return -1;
	}

#ifndef HAVE_WIN32
	// Check the peer certificate against the CRL list only if set
        // in the configuration file. Thus if not set it is not
        // breaking the 'ssl_extra_checks_script' configuration.
	if(confs && ca_x509_verify_crl(confs, peer, ssl_peer_cn))
		return -1;

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
	//if((comp=SSL_get_current_compression(ssl)))
	//	logp("SSL is using compression: %s\n", comp->name);

	return 0;
}
