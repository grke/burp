#include "../burp.h"
#include "../alloc.h"
#include "../asfd.h"
#include "../async.h"
#include "../cmd.h"
#include "../conf.h"
#include "../conffile.h"
#include "../handy.h"
#include "../iobuf.h"
#include "../log.h"
#include "auth.h"

#include <time.h>
#include <assert.h>
#include <openssl/rand.h>

#ifndef UTEST
static
#endif
int compare_password(const char *secret, const char *client_supplied)
{
	int ret, status;

	status = strcmp(secret, client_supplied);

	// To prevent timing attacks passwords a random sleep is inserted when
	// the strings didn't match.
	//
	// Normally a constant-length string comparison would be preferred.
	// That doesn't work well here because the length of the secret value
	// (the configured password) is not known until measured which could
	// leak the length.
	if (status != 0) {
		unsigned char delay_bytes[4] = {0};
		uint32_t delay_nsec = 999999999;

		assert(sizeof(delay_bytes) == sizeof(delay_nsec));

		if (RAND_bytes(delay_bytes, sizeof(delay_bytes)) != 1) {
			unsigned long err = ERR_get_error();
			logp("RAND_bytes failed: %s\n", ERR_error_string(err, NULL));
			// Keep going without random delay
		} else {
			memcpy(&delay_nsec, delay_bytes, sizeof(delay_nsec));
		}

		struct timespec req = {0};

		// Biased, but good enough for the purpose (the random number
		// is not what's important)
		req.tv_nsec = delay_nsec % 1000000000;

		ret = nanosleep(&req, NULL);
		if (ret) {
			logp("nanosleep failed with return value %d: %s\n",
				ret, strerror(errno));
			return -1;
		}
	}

	return status;
}

#ifndef UTEST
static
#endif
int check_passwd(const char *passwd, const char *plain_text)
{
#ifndef HAVE_OPENBSD_OS
#ifdef HAVE_CRYPT
	const char *encrypted=NULL;
	if(!plain_text || !passwd || strlen(passwd)<13)
		return 0;

	encrypted=crypt(plain_text, passwd);
	if (encrypted == NULL) {
		logp("crypt function failed: %s\n", strerror(errno));
		return -1;
	}

	return !compare_password(passwd, encrypted);
#endif
#endif
	logp("Server compiled without crypt support - cannot use passwd option\n");
	return -1;
}

static int check_client_and_password(struct conf **globalcs,
	const char *password, struct conf **cconfs)
{
	const char *cname;
	int password_check;
	// Cannot load it until here, because we need to have the name of the
	// client.
	if(conf_load_clientconfdir(globalcs, cconfs)) return -1;

	cname=get_string(cconfs[OPT_CNAME]);
	password_check=get_int(cconfs[OPT_PASSWORD_CHECK]);

	if(!get_string(cconfs[OPT_SSL_PEER_CN]))
	{
		logp("ssl_peer_cn unset");
		if(cname)
		{
			logp("Falling back to using '%s'\n", cname);
			if(set_string(cconfs[OPT_SSL_PEER_CN], cname))
				return -1;
		}
	}

	cname=get_string(cconfs[OPT_CNAME]);

	if(password_check)
	{
		const char *conf_passwd=get_string(cconfs[OPT_PASSWD]);
		const char *conf_password=get_string(cconfs[OPT_PASSWORD]);
		if(!conf_password && !conf_passwd)
		{
			logp("password rejected for client %s\n", cname);
			return -1;
		}
		// check against plain text
		if(conf_password && compare_password(conf_password, password))
		{
			logp("password rejected for client %s\n", cname);
			return -1;
		}
		// check against encypted passwd
		if(conf_passwd && !check_passwd(conf_passwd, password))
		{
			logp("password rejected for client %s\n", cname);
			return -1;
		}
	}

	if(!get_strlist(cconfs[OPT_KEEP]))
	{
		logp("%s: you cannot set the keep value for a client to 0!\n",
			cname);
		return -1;
	}
	return 0;
}

void version_warn(struct asfd *asfd,
	struct cntr *cntr, struct conf **cconfs)
{
	const char *cname=get_string(cconfs[OPT_CNAME]);
	const char *peer_version=get_string(cconfs[OPT_PEER_VERSION]);
	if(!peer_version || strcmp(peer_version, PACKAGE_VERSION))
	{
		char msg[256]="";

		if(!peer_version || !*peer_version)
			snprintf(msg, sizeof(msg), "Client '%s' has an unknown version. Please upgrade.", cname?cname:"unknown");
		else
			snprintf(msg, sizeof(msg), "Client '%s' version '%s' does not match server version '%s'. An upgrade is recommended.", cname?cname:"unknown", peer_version, PACKAGE_VERSION);
		logw(asfd, cntr, "%s\n", msg);
	}
}

int authorise_server(struct asfd *asfd,
	struct conf **globalcs, struct conf **cconfs)
{
	int ret=-1;
	char *cp=NULL;
	char *password=NULL;
	char *cname=NULL;
	char whoareyou[256]="";
	struct iobuf *rbuf=asfd->rbuf;
	const char *peer_version=NULL;
	if(asfd->read(asfd))
	{
		logp("unable to read initial message\n");
		goto end;
	}
	if(rbuf->cmd!=CMD_GEN || strncmp_w(rbuf->buf, "hello"))
	{
		iobuf_log_unexpected(rbuf, __func__);
		goto end;
	}
	// String may look like...
	// "hello"
	// "hello:(version)"
	// (version) is a version number
	if((cp=strchr(rbuf->buf, ':')))
	{
		cp++;
		if(cp && set_string(cconfs[OPT_PEER_VERSION], cp))
			goto end;
	}
	iobuf_free_content(rbuf);

	snprintf(whoareyou, sizeof(whoareyou), "whoareyou");
	peer_version=get_string(cconfs[OPT_PEER_VERSION]);
	if(peer_version)
	{
		long min_ver=0;
		long cli_ver=0;
		if((min_ver=version_to_long("1.3.2"))<0
		  || (cli_ver=version_to_long(peer_version))<0)
			return -1;
		// Stick the server version on the end of the whoareyou string.
		// if the client version is recent enough.
		if(min_ver<=cli_ver)
		 snprintf(whoareyou, sizeof(whoareyou),
			"whoareyou:%s", PACKAGE_VERSION);
	}

	if(asfd->write_str(asfd, CMD_GEN, whoareyou)
	  || asfd->read(asfd))
	{
		logp("unable to get client name\n");
		goto end;
	}

	if(!(cname=strdup_w(rbuf->buf, __func__)))
		goto end;
	if(!get_int(globalcs[OPT_CNAME_FQDN]))
		strip_fqdn(&cname);
	if(get_int(globalcs[OPT_CNAME_LOWERCASE]))
		strlwr(cname);

	if(set_string(cconfs[OPT_CNAME], cname))
		goto end;
	iobuf_free_content(rbuf);

	if(asfd->write_str(asfd, CMD_GEN, "okpassword")
	  || asfd->read(asfd))
	{
		logp("unable to get password for client %s\n",
			get_string(cconfs[OPT_CNAME]));
		goto end;
	}
	password=rbuf->buf;
	iobuf_init(rbuf);

	if(check_client_and_password(globalcs, password, cconfs))
		goto end;

	if(get_int(cconfs[OPT_VERSION_WARN]))
		version_warn(asfd, get_cntr(globalcs), cconfs);

	logp("auth ok for: %s%s\n", get_string(cconfs[OPT_CNAME]),
		get_int(cconfs[OPT_PASSWORD_CHECK])?
			"":" (no password needed)");

	if(asfd->write_str(asfd, CMD_GEN, "ok"))
		goto end;

	if(set_string(cconfs[OPT_CONNECT_CLIENT], cname))
		goto end;

	ret=0;
end:
	iobuf_free_content(rbuf);
	free_w(&password);
	free_w(&cname);
	return ret;
}
